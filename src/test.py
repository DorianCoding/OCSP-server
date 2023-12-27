#!/usr/bin/env python
from cryptography.x509 import ocsp, load_pem_x509_certificate, ReasonFlags
from datetime import datetime, timedelta, timezone
import sys, os, base64, mysql.connector, logging, signal, configparser, pwd
from cryptography.hazmat.primitives import hashes, serialization
FORMAT = "%(asctime)s %(levelname)s in process %(process)d - %(message)s"
logging.basicConfig(filename='/var/log/ocsp_py.log', encoding='utf-8', level=logging.INFO, format=FORMAT)
def sigterm_handler(_signo, _stack_frame):
	response = ocsp.OCSPResponseBuilder.build_unsuccessful(
		ocsp.OCSPResponseStatus.TRY_LATER
    )
	with open(sys.argv[1],"wb") as file:
		file.write(response.public_bytes(serialization.Encoding.DER))
	logging.error("Script received a kill signal!")
	sys.exit(0)
def trim(text):
	return text.split("#")[0].strip()
def configuration_from_ini(file):
    parser = configparser.ConfigParser()
    parser.read(file)
    return parser
def createcacheresp(response):
	serialnumber=hex(response.serial_number)
	with open(cache + "/" + serialnumber,"wb") as file:
		file.write(response.public_bytes(serialization.Encoding.DER))
def checkit(serialnumber,ocspserial):
	if serialnumber==ocspserial.lower():
		with open(ocspresponse,"rb") as file:
			result=file.read()
		with open(sys.argv[1],"wb") as file:
			file.write(result)
		logging.debug("Sending cached response for OCSP intermediate certificate")
		sys.exit(0)
def existresponse(fileres):
	with open(fileres,"rb") as file:
		try:
			ocsp_resp=ocsp.load_der_ocsp_response(file.read())
		except:
			return False
	if ocsp_resp:
		if ocsp_resp.next_update==None or ocsp_resp.next_update.astimezone(timezone.utc)>datetime.now(timezone.utc):
			return ocsp_resp.public_bytes(serialization.Encoding.DER)
	return False
def timing(time):
	time=trim(time)
	elem=time[-1]
	days=time[:-1]
	if elem.lower()=="y":
		return int(days)*365
	elif elem.lower()=="m":
		return int(days)*30
	elif elem.lower()=="d":
		return int(days)
def error(ex,types="trylater"):
	logging.debug("Error setting : %s",ex)
	if types=="request":
		response = ocsp.OCSPResponseBuilder.build_unsuccessful(
    			ocsp.OCSPResponseStatus.MALFORMED_REQUEST
		)
	elif types=="unauthorized":
		response = ocsp.OCSPResponseBuilder.build_unsuccessful(
    			ocsp.OCSPResponseStatus.UNAUTHORIZED
		)
	else:
		response = ocsp.OCSPResponseBuilder.build_unsuccessful(
    			ocsp.OCSPResponseStatus.TRY_LATER
		)
	try:
		with open(sys.argv[1],"wb") as file:
			file.write(response.public_bytes(serialization.Encoding.DER))
	except:
		pass
	sys.exit(1)
if pwd.getpwuid(os.getuid())[0]!="pycert":
	logging.critical("Bad user. Pycert is required. - Exiting")
	sys.exit(1) #Do not send any data.
signal.signal(signal.SIGTERM, sigterm_handler)
signal.signal(signal.SIGINT, sigterm_handler)
if os.access("/var/www/files/certs/ocsp/config.ini", os.R_OK) == 0: #File is not accessible
	logging.critical("Config file is not detected");
	sys.exit(1)
parser=configuration_from_ini("/var/www/files/certs/ocsp/config.ini")
try:
	log=trim(parser.get("db","log"))
	log=logging.getLevelName(log)
	if not isinstance(log, int):
		logging.critical("Logging level is incorrect")
		sys.exit(1)
	logging.getLogger().setLevel(log)
	host=trim(parser.get("db","host"))
	username=trim(parser.get("db","username"))
	password=trim(parser.get("db","password"))
	db=trim(parser.get("db","db"))
	port=int(trim(parser.get("db","port")))
	socket=trim(parser.get("db","socket"))
	producetime=timing(parser.get("ocsp","producetime"))
	ocspcert=trim(parser.get("ocsp","cert"))
	ocspprivatekey=trim(parser.get("ocsp","pkey"))
	if parser.has_option("ocsp","password"):
		ocsppassword=trim(parser.get("ocsp","password"))
	else:
		ocsppassword=None
	ocspresponse=trim(parser.get("ocsp","ocspresponse"))
	cache=trim(parser.get("ocsp","cache"))
except Exception as ex:
	logging.critical("The configuration file is corrupted! - Exiting... Error is %s",ex)
	error(ex)
logging.debug("All config parameters okay")
try:
	with open(ocspprivatekey,"rb") as file:
		ocspprivatekey=file.read()
except Exception as ex:
	logging.critical("OCSP private key does not exist, is not readable or corrupted on %s - Exiting...",ocspprivatekey)
	error(ex)
cnx=None
response=""
serialnumber="N/A"
try:
	with open(ocspcert,"rb") as file:
		ocspcert=load_pem_x509_certificate(file.read())
	logging.debug("OCSP certificate loaded successfully!")
except:
	logging.critical("Ocspcert is corrupted or not a valid format! - Exiting")
	error(ex)
try:
	try:
		with open(sys.argv[1], 'rb') as file:
			ocsp_req = ocsp.load_der_ocsp_request(file.read())
		serialnumber=hex(ocsp_req.serial_number)
		logging.debug("OCSP request imported! Looking for: %s", serialnumber)
	except Exception as ex:
		logging.critical("Not a valid OCSP request - Exiting")
		error(ex,"request") #Send a malformed request
	checkit(serialnumber,hex(ocspcert.serial_number))
	logging.debug("Certificate is a leaf")
	issuer_hash=ocsp_req.issuer_key_hash
	issuer_name=ocsp_req.issuer_name_hash
	if not os.path.isdir(cache):
		try:
			os.mkdir(cache,700)
			logging.info("Cache folder created")
		except Exception as ex:
			logging.critical("Cache folder does not exist and cannot be created, cannot cache answers")
			error(ex)
	if os.path.exists(os.path.join(cache,serialnumber)):
		resp=existresponse(os.path.join(cache,serialnumber))
		print(resp)
		if resp!=False:
			logging.info("Certificate response for %s sent from cache",serialnumber)
			try:
				with open(sys.argv[1],"wb") as file:
					file.write(resp)
			except Exception as ex:
				logging.error("Error writing cache to file : %s",ex)
				error(ex) #Send try later
			sys.exit(0)
	response=ocsp.OCSPResponseBuilder()
	try:
		if socket=="1":
			cnx = mysql.connector.connect(host=host, user=username, password=password, database=db, unix_socket="/run/mysqld/mysqld.sock")
		else:
			cnx = mysql.connector.connect(host=host, user=username, password=password, database=db, port=port)
	except Exception as ex:
		logging.critical("Cannot connect to database on %s - Exiting",host)
		logging.debug("Error: %s",ex)
		sys.exit(1)
	try:
		cursor = cnx.cursor()
		cursor.execute("SELECT status, revocation_time, revocation_reason, cert FROM list_certs WHERE cert_num=%s", [serialnumber])
		result=cursor.fetchone()
		logging.debug("Database connection success")
	except:
		logging.critical("Cannot fetch data from database as %s",host)
		error(ex)
	revoc_time=None
	revoc_reason=None
	unknowned=False
	hashresp=ocsp_req.hash_algorithm
	nextupdate=datetime.now(timezone.utc)+timedelta(days=producetime)
	if (not result or result is None):
		logging.warning("Cert %s is unknown",serialnumber)
		unknowned=True
	elif (result[0]=="Valid"):
		ocspresponse=ocsp.OCSPCertStatus.GOOD
		logging.info("Cert %s is valid!",serialnumber)
		requestcrt=load_pem_x509_certificate(result[3])
	else:
		ocspresponse=ocsp.OCSPCertStatus.REVOKED
		nextupdate=None
		requestcrt=load_pem_x509_certificate(result[3])
		revoc_reason=ReasonFlags.privilege_withdrawn
		for reason in ReasonFlags:
			if reason.name==result[2]:
				revoc_reason=reason
		revoc_time=datetime.fromisoformat(str(result[1])).astimezone(timezone.utc)
		logging.warning("Cert %s is revoked because %s",(serialnumber,result[2]))
	ocspkey=serialization.load_pem_private_key(ocspprivatekey,password=ocsppassword)
	if not unknowned:
		builder = ocsp.OCSPResponseBuilder()
		builder = builder.add_response(
    		cert=requestcrt, issuer=ocspcert, algorithm=hashresp,
    		cert_status=ocspresponse,
    		this_update=datetime.now(timezone.utc),
    		next_update=nextupdate,
    		revocation_time=revoc_time, revocation_reason=revoc_reason
		).responder_id(
			ocsp.OCSPResponderEncoding.HASH, ocspcert
		)
		response = builder.sign(ocspkey, hashes.SHA256())
		issuer_hash_test=ocsp_req.issuer_key_hash
		issuer_name_test=ocsp_req.issuer_name_hash
		if (issuer_hash_test != issuer_hash and issuer_name_test != issuer_name):
			response = ocsp.OCSPResponseBuilder.build_unsuccessful(
    			ocsp.OCSPResponseStatus.UNAUTHORIZED
			)
			logging.warning("Issuer for %s does not match your issuer! Unauthorized was sent!",serialnumber)
		else:
			createcacheresp(response)
			logging.debug("Response successfully created and cached for %s",serialnumber)
	else:
		response = ocsp.OCSPResponseBuilder.build_unsuccessful(
    		ocsp.OCSPResponseStatus.UNAUTHORIZED
		)
except Exception as ex:
	logging.error("Error with cert %s",serialnumber)
	error(ex,"request")
finally:
	if cnx is not None and cnx.is_connected():
            cnx.close()
with open(sys.argv[1],"wb") as file:
	file.write(response.public_bytes(serialization.Encoding.DER))
sys.exit(0)

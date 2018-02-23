import time
from datetime import datetime;
import calendar
import base64
import hmac
import hashlib
import requests
import os

class AzureREST:

	def __init__(self, account, account_key, version="2014-02-14", proxy={}):
		self.account = account
		self.account_key = account_key
		self.version = version
		self.request_proxy = proxy
		self.date = self.__get_date()

	def __construct_auth(self, verb, default_headers, canonicalized_headers, canonicalized_resource):

		def parse_headers(headers):
			arr = []
			for key in headers:
				if headers[key] != "":
					arr.append(str(key) + ":" + headers[key])
				else:
					arr.append(str(key))
					
			arr.sort()
			return "\n".join(arr) + "\n"

		def parse_resource(resource):
			resource_str = "/" + resource['uri'].get("account", self.account) + "/" + resource['uri']['share'] + "/"

			try:
				resource_str += resource['uri']['directory'] + "/"
				resource_str += resource['uri']['filename']
				try:
					queries = resource['queries']
					for key in queries:
						resource_str += "\n" + key + ":" + queries[key]
				except (AttributeError, KeyError):
					pass # no queries
			except (AttributeError, KeyError):
				# no directory
				resource_str += resource['uri']['filename']

			return resource_str

		verb = verb.upper()
		c_headers = parse_headers(canonicalized_headers)
		c_resource = parse_resource(canonicalized_resource)

		auth_string = verb + "\n" + \
			default_headers.get("Content-Encoding","")     + "\n" +  \
			default_headers.get("Content-Language","")     + "\n" +  \
			default_headers.get("Content-Length","")       + "\n" +  \
			default_headers.get("Content-MD5", "")         + "\n" +  \
			default_headers.get("Content-Type", "")        + "\n" +  \
			default_headers.get("Date", "")                + "\n" +  \
			default_headers.get("If-Modified-Since", "")   + "\n" +  \
			default_headers.get("If-Match", "")            + "\n" +  \
			default_headers.get("If-None-Match", "")       + "\n" +  \
			default_headers.get("If-Unmodified-Since", "") + "\n" +  \
			default_headers.get("Range", "")               + "\n" +  \
			c_headers                                             +  \
			c_resource

		auth_string = unicode(auth_string, "utf-8")
		return auth_string

	def __encode_auth(self, auth_string):
		account_key_decoded = base64.b64decode(self.account_key)
		return base64.b64encode(hmac.new(account_key_decoded, auth_string, digestmod=hashlib.sha256).digest())

	def __get_date(self):
		date = datetime.utcnow()
		day_of_week = (calendar.day_name[date.weekday()])[:3]
		month = (calendar.month_name[date.month])[:3]
		day = date.day
		hour = date.hour
		minute = date.minute
		second = date.second

		# append zeros to anything less than 10
		if day < 10:
			day = "0{}".format(day)
		if hour < 10:
			hour = "0{}".format(hour)
		if minute < 10:
			minute = "0{}".format(minute)
		if second < 10:
			second = "0{}".format(second)

		datestring = "{}, {} {} {} {}:{}:{} GMT".format(day_of_week, day, month, 
																										date.year, hour, minute, second)
		return datestring

	def __read_file(self,file_location):
		with open(file_location, 'r') as fileObject:
			read_data = fileObject.read()
		return read_data

	def create_temp_file(self, data, temp_name):
		with open('/tmp/{}'.format(temp_name), 'w') as fileObject:
			for line in data:
				fileObject.write(line + "\n")

	def send_blob(self, blobname, container, filename, file_type, charset, isFileLocation):
		if isFileLocation:
			file = self.__read_file(filename)
		else:
			file = filename
		account_key_decoded = base64.b64decode(self.account_key)
		put_str = u"PUT\n\n\n{}\n\n{}; charset={}\n\n\n\n\n\n\nx-ms-blob-type:BlockBlob\nx-ms-date:{}\nx-ms-version:{}\n/{}/{}/{}".format(str(len(file)),file_type, charset,self.date,self.version,self.account,container,blobname)
		put_str = put_str.encode('utf8')
		sig_str = base64.b64encode(hmac.new(account_key_decoded, put_str, digestmod=hashlib.sha256).digest())
		headers = {
			"x-ms-blob-type": "BlockBlob",
			"x-ms-date": self.date,
			"x-ms-version": self.version,
			"Authorization": "SharedKey {}:{}".format(self.account, sig_str),
			"Content-Type": "{}; charset={}".format(file_type, charset),
			"Content-Length": str(len(file))
		}

		url = "https://{}.blob.core.windows.net/{}/{}".format(self.account, container, blobname)
		r = requests.put(url, headers=headers, data=file, proxies=self.request_proxy)

		# Check for error
		if r.status_code != 201:
			raise ValueError("Unable to send blob: '{}' in container: '{}'\n{}".format(blobname, container, r.content))

	def delete_blob(self, blobname, container):
		account_key_decoded = base64.b64decode(self.account_key)
		delete_str = u"DELETE\n\n\n0\n\n\n\n\n\n\n\n\nx-ms-date:{}\nx-ms-version:{}\n/{}/{}/{}".format(self.date,self.version,self.account,container,blobname)
		delete_str = delete_str.encode('utf-8')
		sig_str = base64.b64encode(hmac.new(account_key_decoded, delete_str, digestmod=hashlib.sha256).digest())
		headers = {
			"Content-Length": "0",
			"x-ms-date": self.date,
			"x-ms-version": self.version,
			"Authorization": "SharedKey {}:{}".format(self.account, sig_str)
		}

		url = "https://{}.blob.core.windows.net/{}/{}".format(self.account, container, blobname)
		r = requests.delete(url, headers=headers)

		# Check for error
		if r.status_code != 202:
			raise ValueError("Unable to delete blob: '{}' in container: '{}'\n{}".format(blobname, container, r.content))

	def put_range(self, filename, share, directory, file_path):
		try:
			content_length = os.path.getsize(file_path)
			file = self.__read_file(file_path)
			auth_string = self.__construct_auth("PUT", {"Content-Length": str(content_length), "Range": "bytes=0-{}".format(content_length-1)}, 
				{"x-ms-date": self.date, "x-ms-write": "update","x-ms-version": self.version}, 
				{'uri': {'account': self.account, "share": share, "directory": directory, "filename": filename}, 'queries': {'comp': 'range'}})

			sig_str = self.__encode_auth(auth_string)

			headers = {
				"Authorization": "SharedKey {}:{}".format(self.account, sig_str),
				"Content-Length": str(content_length),
				"Range": "bytes=0-{}".format(content_length-1),
				"x-ms-date": self.date,
				"x-ms-write": "update",
				"x-ms-version": self.version
			}

			url = "https://{}.file.core.windows.net/{}/{}/{}?comp=range".format(self.account, share, directory, filename)
			r = requests.put(url, headers=headers, proxies=self.request_proxy, data=file)
			if r.status_code != 201:
				raise ValueError('Error creating file')

		except ValueError as e:
			print e
			print r.content
			print self.date

	def create_file(self, filename, share, directory, file_path):
		try:
			content_length = os.path.getsize(file_path)

			auth_string = self.__construct_auth("PUT", {"Content-Length": "0"}, {"x-ms-date": self.date, "x-ms-version": self.version, 
				"x-ms-content-length": str(content_length), "x-ms-type": "file"}, {"uri": {"account": self.account, "share": share, "directory": directory, "filename": filename}})
			sig_str = self.__encode_auth(auth_string)
			
			headers = {
				"Authorization": "SharedKey {}:{}".format(self.account, sig_str),
				"Content-Length": "0",
				"x-ms-date": self.date,
				"x-ms-version": self.version,
				"x-ms-content-length": str(content_length),
				"x-ms-type": "file",
			}

			url = "https://{}.file.core.windows.net/{}/{}/{}".format(self.account, share, directory, filename)
			r = requests.put(url, headers=headers, proxies=self.request_proxy)
			if r.status_code != 201:
				raise ValueError('Error creating file')
		except ValueError as e:
			print e
			print r.content

	def send_file(self, filename, share, directory, file_path):
		self.create_file(filename, share, directory, file_path)
		self.put_range(filename, share, directory, file_path)
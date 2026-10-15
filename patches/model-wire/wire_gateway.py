"""Model-enclave sidecar. Only the internal model network receives decoded JSON."""
import argparse,hashlib,http.client,json,math,re,socket,threading,time,urllib.parse
from deadline_http import DeadlineConnection,resolve_origin
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from model_wire import CONTENT_TYPE,PROFILES,Profile,HEADER,WireError,decode,encode,fixed_content_length,valid_request_json

class Gateway(ThreadingHTTPServer):
    daemon_threads=True
    def __init__(self,address,profile:Profile,upstream:str,*,timeout:float=300,observe=None,max_inflight:int=32):
        parsed=urllib.parse.urlsplit(upstream)
        if parsed.scheme!='http' or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in ('','/'):raise WireError('Internal model HTTP origin required')
        if not math.isfinite(timeout) or timeout<=0:raise WireError('Finite positive total gateway deadline required')
        self.profile=profile;self.upstream=(parsed.hostname,parsed.port or 80);self.addresses=resolve_origin(*self.upstream);self.timeout=timeout;self.observe=observe or (lambda x:None);self.capacity=threading.BoundedSemaphore(max_inflight)
        self.count_lock=threading.Lock();self.inflight=0;self.completed=0;self.admitted=0
        super().__init__(address,Handler)

class Handler(BaseHTTPRequestHandler):
    protocol_version='HTTP/1.1';server_version='OpalModelWire/1';sys_version=''
    def log_message(self,*args):pass
    def setup(self):
        super().setup();self.connection.settimeout(30)
    def _send(self,body,status,ctype,extra=()):
        self.send_response(status);self.send_header('Content-Type',ctype);self.send_header('Content-Length',str(len(body)));self.send_header('Connection','close')
        for k,v in extra:self.send_header(k,v)
        self.end_headers();self.wfile.write(body);self.close_connection=True
    def _engine(self,method,path,body=None):
        remaining=getattr(self,'request_deadline',time.monotonic()+self.server.timeout)-time.monotonic()
        connection=DeadlineConnection(*self.server.upstream,self.server.addresses,max(.001,remaining))
        started=time.monotonic_ns()
        try:
            connection.request(method,path,body=body,headers={'Content-Type':'application/json','Accept-Encoding':'identity','Connection':'close'})
            reply=connection.getresponse();limit=self.server.profile.response_bytes-HEADER.size if method=='POST' else 65536
            raw=reply.read(limit+1)
            if len(raw)>limit or reply.length not in (None,0):raise WireError('Model response incomplete or exceeds fixed envelope')
            connection.remaining()
            if 300<=reply.status<400:raise WireError('Model redirect forbidden')
            if reply.getheader('Content-Encoding','identity').lower()!='identity':raise WireError('Encoded model response forbidden')
            return reply.status,raw,time.monotonic_ns()-started,reply.getheader('Content-Type','application/json')
        finally:connection.finish()
    def do_GET(self):
        # Operational endpoints are explicitly outside the inference-envelope claim.
        if self.path=='/opal-wire-status':
            with self.server.count_lock:
                value={'schema':'opal_model_wire_status_v1','service':self.server.profile.service,
                       'profile_sha256':self.server.profile.sha256,'inflight_requests':self.server.inflight,
                       'completed_requests':self.server.completed,'admitted_model_requests':self.server.admitted}
            self._send(json.dumps(value,sort_keys=True).encode(),200,'application/json');return
        if self.path not in ('/health','/v1/models','/metrics'):self._send(b'{}',404,'application/json');return
        try:status,body,_,ctype=self._engine('GET',self.path);self._send(body,status,ctype)
        except Exception:self._send(b'{"error":"upstream unavailable"}',502,'application/json')
    def do_POST(self):
        self.request_deadline=time.monotonic()+self.server.timeout
        def abort():
            try:self.connection.shutdown(socket.SHUT_RDWR)
            except OSError:pass
            self.connection.close()
        timer=threading.Timer(self.server.timeout,abort);timer.daemon=True;timer.start()
        with self.server.count_lock:self.server.inflight+=1
        try:self._post()
        finally:
            timer.cancel();timer.join(timeout=1)
            with self.server.count_lock:self.server.inflight-=1;self.server.completed+=1
    def _post(self):
        profile=self.server.profile;started=time.monotonic_ns();request_id=self.headers.get('X-Opal-Wire-Request-ID','')
        if self.path!=profile.endpoint:self._send(b'{}',404,'application/json');return
        if not re.fullmatch('[0-9a-f]{32}',request_id):request_id='0'*32
        request_validated=False;framed=b'';raw=b'';status=400;body=b'{"error":"invalid fixed model envelope"}';model_ns=0;wire_read=0;acquired=False;model_attempted=False
        try:
            fixed_content_length(self.headers,profile.request_bytes)
            if self.headers.get('X-Opal-Wire-Profile')!=profile.sha256:raise WireError('Profile mismatch')
            parts=[]
            try:
                while wire_read<profile.request_bytes:
                    part=self.rfile.read1(min(65536,profile.request_bytes-wire_read))
                    if not part:break
                    parts.append(part);wire_read+=len(part)
            finally:framed=b''.join(parts)
            _,raw=decode(framed,frame_bytes=profile.request_bytes);valid_request_json(raw);request_validated=True
            acquired=self.server.capacity.acquire(blocking=False)
            if not acquired:status=503;body=b'{"error":"model gateway capacity reached"}'
            else:
                with self.server.count_lock:self.server.admitted+=1
                model_attempted=True;model_started=time.monotonic_ns()
                try:status,body,_,_=self._engine('POST',profile.endpoint,raw)
                finally:model_ns=time.monotonic_ns()-model_started
        except WireError:
            status=400 if not acquired else 502;body=b'{"error":"model envelope rejected"}'
        except (OSError,http.client.HTTPException):status=502;body=b'{"error":"model upstream unavailable"}'
        finally:
            if acquired:self.server.capacity.release()
        request_frame_sha256=hashlib.sha256(framed).hexdigest()
        framed=encode(body,frame_bytes=profile.response_bytes,response=True,status=status);prewrite_ns=time.monotonic_ns()-started
        event={'schema':'opal_model_wire_gateway_event_v1','request_id':request_id,'service':profile.service,'profile_sha256':profile.sha256,'request_wire_body_bytes':wire_read,'request_read_complete':wire_read==profile.request_bytes,'request_envelope_verified':request_validated,'response_wire_body_bytes':None,'response_frame_bytes':len(framed),'response_write_complete':False,'model_request_attempted':model_attempted,'model_request_body_bytes':len(raw),'model_request_body_sha256':hashlib.sha256(raw).hexdigest() if raw else None,'model_response_body_bytes':len(body),'model_response_body_sha256':hashlib.sha256(body).hexdigest(),'model_http_ns':model_ns,'gateway_prewrite_ns':prewrite_ns,'inner_status':status}
        extra=[('X-Opal-Wire-Request-Validated','1' if request_validated else '0'),('X-Opal-Wire-Request-SHA256',request_frame_sha256),('X-Opal-Wire-Request-ID',request_id),('X-Opal-Wire-Profile',profile.sha256),('X-Opal-Wire-Model-Ns',f'{model_ns:020d}'),('X-Opal-Wire-Gateway-Prewrite-Ns',f'{prewrite_ns:020d}')]
        try:
            self._send(framed,200,CONTENT_TYPE,extra);event['response_wire_body_bytes']=len(framed);event['response_write_complete']=True
        except (OSError,http.client.HTTPException):pass
        finally:self.server.observe(event)

def main():
    p=argparse.ArgumentParser();p.add_argument('--service',choices=PROFILES,required=True);p.add_argument('--upstream',required=True);p.add_argument('--port',type=int,default=8002);p.add_argument('--host',default='0.0.0.0');p.add_argument('--timeout',type=float,default=300);a=p.parse_args()
    server=Gateway((a.host,a.port),PROFILES[a.service],a.upstream,timeout=a.timeout);server.serve_forever()
if __name__=='__main__':main()

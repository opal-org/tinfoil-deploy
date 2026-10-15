"""Fixed application-body frames; no variable-size fallback or model-token padding."""
import hashlib,json,struct
from dataclasses import dataclass
if __package__:
    from .wire_deadline import DEADLINE_POLICY_SHA256
else:
    from wire_deadline import DEADLINE_POLICY_SHA256

CONTENT_TYPE='application/vnd.opal.model-wire.v1'
MAGIC=b'OPALMW01'
HEADER=struct.Struct('!8sBHI')  # magic, direction, original HTTP status, byte length
MAX_FRAME_BYTES=16*1024*1024

class WireError(ValueError): pass

@dataclass(frozen=True)
class Profile:
    service: str
    endpoint: str
    request_bytes: int
    response_bytes: int
    def __post_init__(self):
        if self.endpoint not in ('/v1/embeddings','/v1/chat/completions'):raise WireError('Unsupported inference endpoint')
        for size in (self.request_bytes,self.response_bytes):
            if type(size) is not int or not HEADER.size+128<=size<=MAX_FRAME_BYTES:raise WireError('Invalid fixed body size')
    @property
    def sha256(self):
        return hashlib.sha256(json.dumps({**self.__dict__,'deadline_policy_sha256':DEADLINE_POLICY_SHA256},sort_keys=True,separators=(',',':')).encode()).hexdigest()

PROFILES={
 'nomic-embed-text':Profile('nomic-embed-text','/v1/embeddings',262144,262144),
 'gpt-oss-20b':Profile('gpt-oss-20b','/v1/chat/completions',1048576,131072),
}

def encode(payload:bytes, *, frame_bytes:int, response:bool=False, status:int=0)->bytes:
    if not isinstance(payload,bytes) or len(payload)>frame_bytes-HEADER.size:raise WireError('Payload exceeds fixed envelope')
    if not HEADER.size<frame_bytes<=MAX_FRAME_BYTES:raise WireError('Invalid fixed body size')
    if (response and not 100<=status<=599) or (not response and status!=0):raise WireError('Invalid inner status')
    return HEADER.pack(MAGIC,2 if response else 1,status,len(payload))+payload+bytes(frame_bytes-HEADER.size-len(payload))

def decode(frame:bytes, *, frame_bytes:int, response:bool=False)->tuple[int,bytes]:
    if len(frame)!=frame_bytes or len(frame)<HEADER.size:raise WireError('Fixed body length mismatch')
    magic,kind,status,size=HEADER.unpack_from(frame)
    if magic!=MAGIC or kind!=(2 if response else 1):raise WireError('Frame identity mismatch')
    if (response and not 100<=status<=599) or (not response and status!=0):raise WireError('Invalid inner status')
    end=HEADER.size+size
    if end>frame_bytes or any(frame[end:]):raise WireError('Invalid payload length or nonzero padding')
    return status,frame[HEADER.size:end]

def valid_request_json(payload:bytes):
    try:
        value=json.loads(payload.decode('utf-8'),parse_constant=lambda x:(_ for _ in ()).throw(WireError('Nonfinite JSON')))
    except (UnicodeError,ValueError,RecursionError) as exc:raise WireError('Invalid model JSON') from exc
    if not isinstance(value,dict) or value.get('stream',False) is not False:raise WireError('Only nonstreaming model JSON objects are supported')
    return value

def fixed_content_length(headers,expected:int):
    lengths=headers.get_all('Content-Length',[])
    if len(lengths)!=1 or lengths[0]!=str(expected):raise WireError('Exact Content-Length required')
    if headers.get('Transfer-Encoding') or headers.get('Content-Encoding','identity').lower()!='identity':raise WireError('Encoded or chunked envelope forbidden')
    if headers.get_content_type()!=CONTENT_TYPE:raise WireError('Envelope content type required')

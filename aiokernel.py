import asyncio
import hmac
import json
import sys
import traceback
import uuid

import zmq
from zantedeschia import AsyncZMQSocket
from IPython.kernel.connect import ConnectionFileMixin

with open(sys.argv[1]) as f:
    cf = json.load(f)

sign_key = cf['key'].encode('ascii')

def sign(data):
    h = hmac.new(sign_key, digestmod='sha256')
    for d in data:
        h.update(d)
    return h.hexdigest()

class Message:
    def __init__(self, identitites, header, parent_header, metadata, content,
                 buffers=None):
        self.buffers = buffers
        self.content = content
        self.metadata = metadata
        self.parent_header = parent_header
        self.header = header
        self.identitites = identitites

    @classmethod
    def from_wire(cls, data):
        ix = data.index(b'<IDS|MSG>')
        identities = data[:ix]

        signature = data[ix+1].decode('ascii')
        sig_calculated = sign(data[ix+2:ix+6])
        if not hmac.compare_digest(signature, sig_calculated):
            raise ValueError("Invalid signature")

        def getjson(i):
            return json.loads(data[i].decode('utf-8'))
        header = getjson(ix+2)
        parent_header = getjson(ix+3)
        metadata = getjson(ix+4)
        content = getjson(ix+5)
        buffers = data[ix+6:]
        return cls(identities, header, parent_header, metadata, content, buffers)

    def to_wire(self):
        main = [json.dumps(d).encode('utf-8') for d in
                (self.header, self.parent_header, self.metadata, self.content)]
        signature = sign(main).encode('ascii')
        return self.identitites + [b'<IDS|MSG>', signature] + main + (self.buffers or [])

    def reply(self, msg_type):
        new_header = {'msg_id': str(uuid.uuid4()),
                      'username': self.header['username'],
                      'session': self.header['session'],
                      'msg_type': msg_type,
                      'version': '5.0',
                      }
        return type(self)(self.identitites, new_header, self.header, {}, {})

kernel_info_reply = {'protocol_version': '5.0',
                     'implementation': 'aio_kernel',
                     'implementation_version': '0.1',
                     'language_info': {
                         'name': 'python',
                         'version': sys.version.split()[0],
                         'mimetype': 'text/x-python',
                         'codemirror_mode': {'name': 'python',
                                             'version': sys.version_info[0]},
                         'pygments_lexer': 'python3',
                         'nbconvert_exporter': 'python',
                         'file_extension': '.py'
                     },
                     'banner': 'AsyncIO kernel'
                    }

class MyStream:
    execute_msg = None
    def __init__(self, name, iopub_socket):
        assert name in {'stdout', 'stderr'}
        self.name = name
        self.iopub_socket = iopub_socket
    
    def write(self, text):
        r = self.execute_msg.reply('stream')
        r.content = {'name':self.name, 'text': text}
        self.iopub_socket.send_multipart(r.to_wire())
    
    def flush(self):
        pass

class Kernel:
    _saved_stdout = None
    _saved_stderr = None

    def __init__(self):
        self.cf = cf
        self.ctx = zmq.Context()
        shell_sock = self.ctx.socket(zmq.ROUTER)
        shell_sock.bind(self._url('shell'))
        self.shell_socket = AsyncZMQSocket(shell_sock)
        iopub_sock = self.ctx.socket(zmq.PUB)
        iopub_sock.bind(self._url('iopub'))
        self.iopub_socket = AsyncZMQSocket(iopub_sock)
        stdin_sock = self.ctx.socket(zmq.ROUTER)
        stdin_sock.bind(self._url('stdin'))
        self.stdin_socket = AsyncZMQSocket(stdin_sock)
        ctrl_sock = self.ctx.socket(zmq.ROUTER)
        ctrl_sock.bind(self._url('control'))
        self.control_socket = AsyncZMQSocket(ctrl_sock)
        hb_sock = self.ctx.socket(zmq.REP)
        hb_sock.bind(self._url('hb'))
        self.hb_socket = AsyncZMQSocket(hb_sock)
        
        self.hb_socket.on_recv(self.hb_echo)
        self.shell_socket.on_recv(self.incoming_message)
        self.control_socket.on_recv(self.incoming_message)
        
        self.stdout = MyStream('stdout', self.iopub_socket)
        self.stderr = MyStream('stderr', self.iopub_socket)
        
        self.exec_counter = 0
        self.user_ns = {}
    
    def _url(self, channel):
        port = channel + '_port'
        return self.cf['transport'] + '://' + self.cf['ip'] + ':' + str(self.cf[port])
    
    def hb_echo(self, msg_parts):
        self.hb_socket.send_multipart(msg_parts)
    
    accepted_msg_types = {'kernel_info_request', 'execute_request'}
    
    def incoming_message(self, msg_parts):
        msg = Message.from_wire(msg_parts)
        if msg.header['msg_type'] not in self.accepted_msg_types:
            return
        
        getattr(self, msg.header['msg_type'])(msg)

    def kernel_info_request(self, msg):
        r = msg.reply('kernel_info_reply')
        r.content = kernel_info_reply
        self.shell_socket.send_multipart(r.to_wire())
    
    def status(self, state, parent):
        r = parent.reply('status')
        r.content = {'execution_state': state}
        self.iopub_socket.send_multipart(r.to_wire())
    
    def enable_stream_capture(self, msg):
        self._saved_stdout = sys.stdout
        self._saved_stderr = sys.stderr
        self.stdout.execute_msg = msg
        self.stderr.execute_msg = msg
        sys.stdout = self.stdout
        sys.stderr = self.stderr

    def disable_stream_capture(self):
        sys.stdout = self._saved_stdout
        sys.stderr = self._saved_stderr
    
    def execute_request(self, msg):
        self.status('busy', msg)
        
        silent = msg.content['silent']
        if not silent:
            self.enable_stream_capture(msg)
        
        status = 'ok'
        self.exec_counter += 1
        try:
            exec(msg.content['code'], self.user_ns)
        except Exception as e:
            status = 'error'
            err_info = {'ename': type(e).__name__,
                        'evalue': str(e),
                        'traceback': traceback.format_tb(e.__traceback__)
                       }
            e = msg.reply('error')
            e.content = err_info
            self.iopub_socket.send_multipart(e.to_wire())
        except KeyboardInterrupt:
            status = 'abort'
        
        if not silent:
            self.disable_stream_capture()
            
        r = msg.reply('execute_reply')
        r.content = {'status': status, 'execution_count': self.exec_counter}
        if status == 'ok':
            r.content.update(payload=[], user_expressions={})
        elif status == 'error':
            r.content.update(err_info)
        
        self.shell_socket.send_multipart(r.to_wire())
        self.status('idle', msg)

k = Kernel()
loop = asyncio.get_event_loop()
loop.call_later(3, k.shell_socket._wakeup)
loop.run_forever()

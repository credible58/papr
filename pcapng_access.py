import socket
import json
import re
import pandas as pd

def get_json_bytes(json_string):
    return bytes((json_string + '\n'), 'utf-8')


class SharkdDataAccess:
    json_trace = False
    s = ""
    is_connected = False
    rpcid = 0
    columns = []

    def start_session(self, ip_address, port):
        host = socket.gethostbyname(ip_address)
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if self.json_trace:
            print('c: Connecting to ' + host + ':' + str(port))
        self.s.connect((host, port))
        self.is_connected = True

    def rpc_send_recv(self, method, params):
        rc = 0
        self.rpcid += 1
        data = bytearray()

        request  = '{'
        request += '"jsonrpc":"2.0"'
        request += ', "id":' + str(self.rpcid)
        request += ', "method":"' + method + '"'
        if params:
            request += ', "params":{' + params + '}'
        request += '}'

        self.s.sendall(get_json_bytes(request))
        if self.json_trace:
            print('s: ' + request)

        while True:
            segment = self.s.recv(8 * 1024)
            data.extend(segment)
            seg_len = len(segment)
            if segment[seg_len-1] == 10:  # check for \n character - 0x0a or 10
                break

        rx_data = data[:-2].decode('utf-8')
        if self.json_trace:
            print('r: ' + rx_data)

        try:
            recv_json = json.loads(rx_data)
        except ValueError:
            recv_json = {}
            rc = -1

        if 'result' in recv_json:
            return recv_json, 0, ""
        else:
            print(recv_json, recv_json['error']['code'], recv_json['error']['message'])
            exit(-1)

    def init_schema(self, cols):
        self.columns = []
        self.df2 = pd.DataFrame(columns=cols)
        for col in cols:
            params = f'"field":"{col}"'
            col_spec =  self.rpc_send_recv('complete', params)

            new_column = {'name':col_spec[0]['result']['field'][0]['f'],
                          'ws_type':col_spec[0]['result']['field'][0]['t']}

            self.columns.append(new_column)

        return

    def ft_string(self, value_in):
        return value_in

    def ft_boolean(self, value_in):
        # ToDo: Add logic
        value_out = value_in
        return value_out

    def ft_integer(self, value_in):
        if value_in == '':
            return None
        # need to guard against example where we get ip.id style
        # of value e.g. '0x9a5f (39519)'
        try:
            value_out = int(value_in)
        except:
            try:
                value_out = value_in.split()[1]
            except:
                return int(value_in, 16)
            value_out = re.sub('[()]', '', value_out)
        return int(value_out)

    def ft_float(self, value_in):
        if value_in == '':
            return None
        return float(value_in)

    def ft_bytearray(self, value_in):
        # ToDo: Fix this
        return value_in

    def switch_ftype(self, ws_value, col_index):
        ft_string = self.ft_string
        ft_boolean = self.ft_boolean
        ft_integer = self.ft_integer
        ft_float = self.ft_float
        ft_bytearray = self.ft_bytearray

        switcher = {
            0: ft_string,
            1: ft_string,
            2: ft_boolean,
            3: ft_string,
            4: ft_integer,
            5: ft_integer,
            6: ft_integer,
            7: ft_integer,
            8: ft_integer,
            9: ft_integer,
            10: ft_integer,
            11: ft_integer,
            12: ft_integer,
            13: ft_integer,
            14: ft_integer,
            15: ft_integer,
            16: ft_integer,
            17: ft_integer,
            18: ft_integer,
            19: ft_integer,
            20: ft_float,
            21: ft_float,
            22: ft_float,
            23: ft_float,
            24: ft_string,
            25: ft_float,
            26: ft_string,
            27: ft_string,
            28: ft_string,
            29: ft_bytearray,
            30: ft_bytearray,
            31: ft_bytearray,
            32: ft_string,
            33: ft_string,
            34: ft_string,
            35: ft_integer,
            36: ft_string,
            37: ft_string,
            38: ft_string,
            39: ft_string,
            40: ft_string,
            41: ft_string,
            42: ft_string,
            43: ft_string,
            44: ft_string,
            45: ft_string,
            46: ft_string,
        }
        func = switcher.get(self.columns[col_index]['ws_type'], ft_string)
        # Execute the function
        return func(ws_value)

    def close_session(self):
        if self.json_trace:
            peername = self.s.getpeername()
            print('c: Closing connection to: ' + peername[0] + ':' + str(peername[1]))
        self.s.close()
        self.is_connected = False


# Wireshark field types
# enum ftenum {
# 0	FT_NONE,	/* used for text labels with no value */
# 1	FT_PROTOCOL,
# 2	FT_BOOLEAN,	/* TRUE and FALSE come from <glib.h> */
# 3	FT_CHAR,	/* 1-octet character as 0-255 */
# 4	FT_UINT8,
# 5	FT_UINT16,
# 6	FT_UINT24,	/* really a UINT32, but displayed as 6 hex-digits if FD_HEX*/
# 7	FT_UINT32,
# 8	FT_UINT40,	/* really a UINT64, but displayed as 10 hex-digits if FD_HEX*/
# 9	FT_UINT48,	/* really a UINT64, but displayed as 12 hex-digits if FD_HEX*/
# 10	FT_UINT56,	/* really a UINT64, but displayed as 14 hex-digits if FD_HEX*/
# 11	FT_UINT64,
# 12	FT_INT8,
# 13	FT_INT16,
# 14	FT_INT24,	/* same as for UINT24 */
# 15	FT_INT32,
# 16	FT_INT40, /* same as for UINT40 */
# 17	FT_INT48, /* same as for UINT48 */
# 18	FT_INT56, /* same as for UINT56 */
# 19	FT_INT64,
# 20	FT_IEEE_11073_SFLOAT,
# 21	FT_IEEE_11073_FLOAT,
# 22	FT_FLOAT,
# 23	FT_DOUBLE,
# 24	FT_ABSOLUTE_TIME,
# 25	FT_RELATIVE_TIME,
# 26	FT_STRING,	/* counted string, with no null terminator */
# 27	FT_STRINGZ,	/* null-terminated string */
# 28	FT_UINT_STRING,	/* counted string, with count being the first part of the value */
# 29	FT_ETHER,
# 30	FT_BYTES,
# 31	FT_UINT_BYTES,
# 32	FT_IPv4,
# 33	FT_IPv6,
# 34	FT_IPXNET,
# 35	FT_FRAMENUM,	/* a UINT32, but if selected lets you go to frame with that number */
# 36	FT_PCRE,	/* a compiled Perl-Compatible Regular Expression object */
# 37	FT_GUID,	/* GUID, UUID */
# 38	FT_OID,		/* OBJECT IDENTIFIER */
# 39	FT_EUI64,
# 40	FT_AX25,
# 41	FT_VINES,
# 42	FT_REL_OID,	/* RELATIVE-OID */
# 43	FT_SYSTEM_ID,
# 44	FT_STRINGZPAD,	/* null-padded string */
# 45	FT_FCWWN,
# 46	FT_STRINGZTRUNC,	/* null-truncated string */
# 47	FT_NUM_TYPES /* last item number plus one */
# };

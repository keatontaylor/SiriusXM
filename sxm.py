import argparse
import requests
import base64
import urllib.parse
import json
import time, datetime
import sys
import os
import struct
from http.server import BaseHTTPRequestHandler, HTTPServer
from Crypto.Cipher import AES
from mutagen.id3 import ID3, TIT2, TPE1, APIC, ID3NoHeaderError
from io import BytesIO


class SiriusXM:
    USER_AGENT = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/604.5.6 (KHTML, like Gecko) Version/11.0.3 Safari/604.5.6'
    REST_FORMAT = 'https://player.siriusxm.com/rest/v2/experience/modules/{}'
    LIVE_PRIMARY_HLS = 'https://siriusxm-priprodlive.akamaized.net'

    def __init__(self, username, password):
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': self.USER_AGENT})
        self.username = username
        self.password = password
        self.playlists = {}
        self.current_title = ""
        self.current_artist = ""
        self.current_channel = ""
        self.current_channel_id = ""
        self.current_channel_id_user = ""
        self.current_metadata = None
        self.channels = None

    @staticmethod
    def log(x):
        print('{} <SiriusXM>: {}'.format(datetime.datetime.now().strftime('%d.%b %Y %H:%M:%S'), x))

    def is_logged_in(self):
        return 'SXMDATA' in self.session.cookies

    def is_session_authenticated(self):
        return 'AWSALB' in self.session.cookies and 'JSESSIONID' in self.session.cookies

    def get(self, method, params, authenticate=True):
        if authenticate and not self.is_session_authenticated() and not self.authenticate():
            self.log('Unable to authenticate')
            return None

        res = self.session.get(self.REST_FORMAT.format(method), params=params)
        if res.status_code != 200:
            self.log('Received status code {} for method \'{}\''.format(res.status_code, method))
            return None

        try:
            return res.json()
        except ValueError:
            self.log('Error decoding json for method \'{}\''.format(method))
            return None

    def post(self, method, postdata, authenticate=True):
        if authenticate and not self.is_session_authenticated() and not self.authenticate():
            self.log('Unable to authenticate')
            return None

        res = self.session.post(self.REST_FORMAT.format(method), data=json.dumps(postdata))
        if res.status_code != 200:
            self.log('Received status code {} for method \'{}\''.format(res.status_code, method))
            return None

        try:
            return res.json()
        except ValueError:
            self.log('Error decoding json for method \'{}\''.format(method))
            return None

    def login(self):
        postdata = {
            'moduleList': {
                'modules': [{
                    'moduleRequest': {
                        'resultTemplate': 'web',
                        'deviceInfo': {
                            'osVersion': 'Mac',
                            'platform': 'Web',
                            'sxmAppVersion': '3.1802.10011.0',
                            'browser': 'Safari',
                            'browserVersion': '11.0.3',
                            'appRegion': 'US',
                            'deviceModel': 'K2WebClient',
                            'clientDeviceId': 'null',
                            'player': 'html5',
                            'clientDeviceType': 'web',
                        },
                        'standardAuth': {
                            'username': self.username,
                            'password': self.password,
                        },
                    },
                }],
            },
        }
        data = self.post('modify/authentication', postdata, authenticate=False)
        if not data:
            return False

        try:
            return data['ModuleListResponse']['status'] == 1 and self.is_logged_in()
        except KeyError:
            self.log('Error decoding json response for login')
            return False

    def authenticate(self):
        if not self.is_logged_in() and not self.login():
            self.log('Unable to authenticate because login failed')
            return False

        postdata = {
            'moduleList': {
                'modules': [{
                    'moduleRequest': {
                        'resultTemplate': 'web',
                        'deviceInfo': {
                            'osVersion': 'Mac',
                            'platform': 'Web',
                            'clientDeviceType': 'web',
                            'sxmAppVersion': '3.1802.10011.0',
                            'browser': 'Safari',
                            'browserVersion': '11.0.3',
                            'appRegion': 'US',
                            'deviceModel': 'K2WebClient',
                            'player': 'html5',
                            'clientDeviceId': 'null'
                        }
                    }
                }]
            }
        }
        data = self.post('resume?OAtrial=false', postdata, authenticate=False)
        if not data:
            return False

        try:
            return data['ModuleListResponse']['status'] == 1 and self.is_session_authenticated()
        except KeyError:
            self.log('Error parsing json response for authentication')
            return False

    def get_sxmak_token(self):
        try:
            return self.session.cookies['SXMAKTOKEN'].split('=', 1)[1].split(',', 1)[0]
        except (KeyError, IndexError):
            return None

    def get_gup_id(self):
        try:
            return json.loads(urllib.parse.unquote(self.session.cookies['SXMDATA']))['gupId']
        except (KeyError, ValueError):
            return None

    def get_playlist_url(self, guid, channel_id, use_cache=True, max_attempts=5):
        if use_cache and channel_id in self.playlists:
             return self.playlists[channel_id]

        params = {
            'assetGUID': guid,
            'ccRequestType': 'AUDIO_VIDEO',
            'channelId': channel_id,
            'hls_output_mode': 'custom',
            'marker_mode': 'all_separate_cue_points',
            'result-template': 'web',
            'time': int(round(time.time() * 1000.0)),
            'timestamp': datetime.datetime.now(datetime.UTC).isoformat('T') + 'Z'
        }
        data = self.get('tune/now-playing-live', params)
        if not data:
            return None

        try:
            status = data['ModuleListResponse']['status']
            musicdata = data['ModuleListResponse']['moduleList']['modules'][0]['moduleResponse']['liveChannelData']
            station = musicdata['markerLists'][0]['markers'][0]['episode']['longTitle']

            musicdata = data['ModuleListResponse']['moduleList']['modules'][0]['moduleResponse']['liveChannelData']
            self.current_metadata = musicdata['markerLists'][-1]['markers'][-1]['cut']

            data_to_log = {
                'title': musicdata['markerLists'][-1]['markers'][-1]['cut']['title'],
                'artist': musicdata['markerLists'][-1]['markers'][-1]['cut']['artists'][0]['name'],
                'station': station,
                'playing': True,
            }
            self.current_title = data_to_log["title"]
            self.current_artist = data_to_log["artist"]
            message = data['ModuleListResponse']['messages'][0]['message']
            message_code = data['ModuleListResponse']['messages'][0]['code']
        except (KeyError, IndexError):
            self.log('Error parsing json response for playlist')
            return None

        # login if session expired
        if message_code == 201 or message_code == 208:
            if max_attempts > 0:
                self.log('Session expired, logging in and authenticating')
                if self.authenticate():
                    self.log('Successfully authenticated')
                    return self.get_playlist_url(guid, channel_id, use_cache, max_attempts - 1)
                else:
                    self.log('Failed to authenticate')
                    return None
            else:
                self.log('Reached max attempts for playlist')
                return None
        elif message_code != 100:
            self.log('Received error {} {}'.format(message_code, message))
            return None

        # get m3u8 url
        try:
            playlists = data['ModuleListResponse']['moduleList']['modules'][0]['moduleResponse']['liveChannelData']['hlsAudioInfos']
        except (KeyError, IndexError):
            self.log('Error parsing json response for playlist')
            return None
        for playlist_info in playlists:
            if playlist_info['size'] == 'LARGE':
                playlist_url = playlist_info['url'].replace('%Live_Primary_HLS%', self.LIVE_PRIMARY_HLS)
                self.playlists[channel_id] = self.get_playlist_variant_url(playlist_url)
                return self.playlists[channel_id]

        return None

    def get_playlist_variant_url(self, url):
        params = {
            'token': self.get_sxmak_token(),
            'consumer': 'k2',
            'gupId': self.get_gup_id(),
        }
        res = self.session.get(url, params=params)

        if res.status_code != 200:
            self.log('Received status code {} on playlist variant retrieval'.format(res.status_code))
            return None
        
        for x in res.text.split('\n'):
            if x.rstrip().endswith('.m3u8'):
                return '{}/{}'.format(url.rsplit('/', 1)[0], x.rstrip())
        
        return None

    def get_playlist(self, name, use_cache=True):
        guid, channel_id, channel_name, logo, channel_id_user = self.get_channel(name)
        self.current_channel = channel_name
        self.current_channel_id = channel_id
        self.current_channel_id_user = channel_id_user

        if not guid or not channel_id:
            self.log('No channel for {}'.format(name))
            return None

        url = self.get_playlist_url(guid, channel_id, use_cache)
        if not url:
            return None

        params = {
            'token': self.get_sxmak_token(),
            'consumer': 'k2',
            'gupId': self.get_gup_id(),
        }
        res = self.session.get(url, params=params)

        if res.status_code == 403:
            self.log('Received status code 403 on playlist, renewing session')
            return self.get_playlist(name, False)

        if res.status_code != 200:
            self.log('Received status code {} on playlist variant'.format(res.status_code))
            return None

        base_url = url.rsplit('/', 1)[0]
        base_path = base_url[8:].split('/', 1)[1]
        lines = res.text.split('\n')
        new_lines = []

        for line in lines:
            line = line.rstrip()
            # Skip any existing EXTINF for .aac segments
            if line.startswith('#EXTINF'):
                continue
            if line.endswith('.aac'):
                duration = 10.0  # VLC usually ignores, optional
                new_lines.append(f'#EXTINF:{duration} tvg-logo="{logo}" tvc-guide-art="{logo}",{self.current_artist} - {self.current_title}')
                new_lines.append(f'{base_path}/{line}')
            else:
                new_lines.append(line)

        return '\n'.join(new_lines)


    def get_segment(self, path, max_attempts=5):
        url = '{}/{}'.format(self.LIVE_PRIMARY_HLS, path)
        params = {
            'token': self.get_sxmak_token(),
            'consumer': 'k2',
            'gupId': self.get_gup_id(),
        }
        res = self.session.get(url, params=params)

        self.get_playlist(path.split('/', 2)[1], False)

        if res.status_code == 403:
            if max_attempts > 0:
                self.log('Received status code 403 on segment, renewing session')
                self.get_playlist(path.split('/', 2)[1], False)
                return self.get_segment(path, max_attempts - 1)
            else:
                self.log('Received status code 403 on segment, max attempts exceeded')
                return None

        if res.status_code != 200:
            self.log('Received status code {} on segment'.format(res.status_code))
            return None

        return res.content

    def get_channels(self):
        if not self.channels:
            postdata = {
                'moduleList': {
                    'modules': [{
                        'moduleArea': 'Discovery',
                        'moduleType': 'ChannelListing',
                        'moduleRequest': {
                            'consumeRequests': [],
                            'resultTemplate': 'responsive',
                            'alerts': [],
                            'profileInfos': []
                        }
                    }]
                }
            }
            data = self.post('get', postdata)
            if not data:
                self.log('Unable to get channel list')
                return []

            try:
                self.channels = data['ModuleListResponse']['moduleList']['modules'][0]['moduleResponse']['contentData']['channelListing']['channels']
            except (KeyError, IndexError):
                self.log('Error parsing json response for channels')
                return []
        return self.channels

    def get_channel(self, name):
        name = name.lower()
        for x in self.get_channels():
            if x.get('name', '').lower() == name or x.get('channelId', '').lower() == name or x.get('siriusChannelNumber') == name:
                return (x['channelGuid'], x['channelId'], x['name'], x['images']['images'][3]['url'], x['siriusChannelNumber'])
        return (None, None)


    def channels_to_m3u(self):
        # Get channels sorted by favorite and channel number
        channels = list(sorted(
            self.get_channels(),
            key=lambda x: (not x.get('isFavorite', False), int(x.get('siriusChannelNumber', 9999)))
        ))
        
        m3u_lines = ["#EXTM3U"]
        for ch in channels:
            cid = ch.get('channelId', '')
            cnum = ch.get('siriusChannelNumber', '')
            name = ch.get('name', 'Unknown')
            stream_url = f"/{cid}.m3u8"

            # Safe fetch — some channels may not have artwork or arrays may be short
            logo = (
                ch.get("images", {})
                .get("images", [{}]*4)[3]  # ensures index safety
                .get("url", "")
            )

            # M3U metadata with channel art
            m3u_lines.append(
                f'#EXTINF:-1 tvg-id="{cid}" tvg-logo="{logo}",{cnum} {name}'
            )
            m3u_lines.append(stream_url)
        return "\n".join(m3u_lines)

    def channels_to_xspf(self):
        import xml.etree.ElementTree as ET
        from xml.dom import minidom

        # Root playlist element
        playlist = ET.Element("playlist", version="1", xmlns="http://xspf.org/ns/0/")
        tracklist = ET.SubElement(playlist, "trackList")

        # Get channels sorted by favorite and channel number
        channels = sorted(
            self.get_channels(),
            key=lambda x: (not x.get('isFavorite', False), int(x.get('siriusChannelNumber', 9999)))
        )

        for ch in channels:
            cid = ch.get('channelId', '')
            cnum = ch.get('siriusChannelNumber', '')
            name = ch.get('name', 'Unknown')
            stream_url = f"/{cid}.m3u8"

            # Safe fetch of logo
            logo = (
                ch.get("images", {})
                .get("images", [{}]*4)[3]  # ensures index safety
                .get("url", "")
            )

            # Create a track element
            track = ET.SubElement(tracklist, "track")
            ET.SubElement(track, "location").text = stream_url
            ET.SubElement(track, "title").text = f"{cnum} {name}"
            ET.SubElement(track, "identifier").text = cid
            if logo:
                ET.SubElement(track, "image").text = logo

        # Pretty print XML
        xml_str = ET.tostring(playlist, encoding='utf-8')
        pretty_xml = minidom.parseString(xml_str).toprettyxml(indent="  ")
        return pretty_xml

    def decrypt_and_inject_id3_plain(self, data, aes_key, artist, title, channel_name, channel_id, album_art_url=None):

        # --- Decrypt AES-CBC ---
        iv = data[:16]
        ciphertext = data[16:]
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(ciphertext)

        # Remove AES padding
        pad_len = decrypted[-1]
        if 0 < pad_len <= 16:
            decrypted = decrypted[:-pad_len]

        # Strip existing ID3
        if decrypted[:3] == b'ID3':
            size_bytes = decrypted[6:10]
            size = (size_bytes[0]<<21)|(size_bytes[1]<<14)|(size_bytes[2]<<7)|size_bytes[3]
            decrypted = decrypted[size+10:]

        # --- Build ID3v2.3 frames ---
        def make_text_frame(frame_id, text):
            encoded = text.encode('utf-16')  # UTF-16 with BOM
            size = len(encoded) + 1
            header = frame_id.encode('ascii') + struct.pack('>I', size) + b'\x00\x00'
            return header + b'\x01' + encoded

        frames = make_text_frame("TIT2", channel_id + " " + channel_name + " | " + title) + make_text_frame("TPE1", artist)

        # --- Build ID3 header ---
        size = len(frames)
        def syncsafe(i):
            return bytes([(i >> 21) & 0x7F, (i >> 14) & 0x7F, (i >> 7) & 0x7F, i & 0x7F])
        header = b"ID3" + b"\x03\x00" + b"\x00" + syncsafe(size)

        tag = header + frames

        return tag + decrypted


    def inject_id3_mutagen(self, aac_data, artist, title, channel_name, channel_id, album_art_url=None):
        """
        aac_data: raw AAC data (bytes)
        Returns: AAC data with prepended ID3v2.3 tag
        """
        # Create a new ID3 tag
        id3 = ID3()

        # Title and artist frames
        id3.add(TIT2(encoding=3, text=f"{channel_id} {channel_name} | {title}"))  # UTF-8
        id3.add(TPE1(encoding=3, text=artist))

        # Album art frame
        if album_art_url:
            try:
                resp = requests.get(album_art_url)
                resp.raise_for_status()
                img_data = resp.content
                mime = "image/jpeg" if album_art_url.lower().endswith((".jpg", ".jpeg")) else "image/png"
                id3.add(APIC(
                    encoding=3,          # UTF-8
                    mime=mime,
                    type=3,              # front cover
                    desc=u'Cover',
                    data=img_data
                ))
            except Exception as e:
                print("Failed to fetch album art:", e)

        # Write tag to memory
        output = BytesIO()
        id3.save(output, v2_version=3)  # ID3v2.3 for best compatibility
        tag_bytes = output.getvalue()

        # Prepend tag to AAC data
        return tag_bytes + aac_data

# ---------------------- HTTP Handler ------------------------
def make_sirius_handler(sxm):
    class SiriusHandler(BaseHTTPRequestHandler):
        HLS_AES_KEY = base64.b64decode('0Nsco7MAgxowGvkUT8aYag==')

        # Override log_message to append extra info
        def log_message(self, format, *args):
            if self.path.endswith('.m3u8'):
                extra_info = f"[Current Channel: {sxm.current_channel, sxm.current_channel_id}]"
            else:
                extra_info = f"[Playing Now: {sxm.current_title, sxm.current_artist}]"  # Anything you want to append
            # Original log format is: "%s - - [%s] %s\n"
            super().log_message(format + " %s", *args, extra_info)

        def do_GET(self):
            if self.path == "/" or self.path == "/index.html":
                try:
                    with open("index.html", "rb") as f:
                        content = f.read()

                    self.send_response(200)
                    self.send_header("Content-type", "text/html")
                    self.end_headers()
                    self.wfile.write(content)
                    return

                except FileNotFoundError:
                    self.send_error(404, "index.html not found")
                    return
            elif self.path.startswith("/proxy/"):
                raw_url = urllib.parse.unquote(self.path.replace("/proxy/", "", 1))  # strip prefix

                # must only allow SiriusXM hosts (security)
                allowed_hosts = [
                    "albumart.siriusxm.com",
                    "pri.art.prod.streaming.siriusxm.com",
                    "art.siriusxm.com"
                ]
                parsed = urllib.parse.urlparse(raw_url)

                if parsed.netloc not in allowed_hosts:
                    self.send_error(403, "Domain not allowed")
                    return

                try:
                    r = requests.get(raw_url, timeout=10)
                    self.send_response(r.status_code)
                    self.send_header("Content-Type", r.headers.get("Content-Type", "image/png"))
                    self.send_header("Cache-Control", "public, max-age=86400")  # cache 1 day
                    self.end_headers()
                    self.wfile.write(r.content)
                except Exception as e:
                    self.send_error(500, f"Proxy request failed: {e}")
                return
            elif self.path.endswith(".m3u"):
                playlist = sxm.channels_to_m3u()
                if playlist:
                    self.send_response(200)
                    self.send_header("Content-Type", "audio/mpegurl")
                    self.end_headers()
                    self.wfile.write(playlist.encode("utf-8"))
                else:
                    self.send_error(404, "No channels available")
            elif self.path.endswith(".xspf"):
                playlist = sxm.channels_to_xspf()
                if playlist:
                    self.send_response(200)
                    self.send_header("Content-Type", "application/xspf+xml")
                    self.end_headers()
                    self.wfile.write(playlist.encode("utf-8"))
                else:
                    self.send_error(404, "No channels available")
            elif self.path.endswith(".json"):
                if sxm.current_metadata:
                    self.send_response(200)
                    self.send_header("Content-Type", "text/json")
                    self.end_headers()
                    self.wfile.write(json.dumps(sxm.current_metadata).encode("utf-8"))
                else:
                    self.send_error(404, "No channels available")
            elif self.path.endswith(".png"):
                if sxm.current_metadata:
                    with open("play.png", "rb") as f:
                        content = f.read()
                    self.send_response(200)
                    self.send_header("Content-Type", "image/png")
                    self.end_headers()
                    self.wfile.write(content)
                else:
                    self.send_error(404, "No channels available")
            elif self.path.endswith('.m3u8'):
                data = sxm.get_playlist(self.path.rsplit('/', 1)[1][:-5])
                if data:
                    # Remove any AES key lines
                    lines = [line for line in data.split('\n') if not line.startswith('#EXT-X-KEY')]
                    clean_playlist = '\n'.join(lines)

                    self.send_response(200)
                    self.send_header('Content-Type', 'application/x-mpegURL')
                    self.end_headers()
                    self.wfile.write(clean_playlist.encode('utf-8'))
                else:
                    self.send_response(500)
                    self.end_headers()
            elif self.path.endswith('.aac'):
                data = sxm.get_segment(self.path[1:])
                if data:
                    # Decrypt and prepend ID3v2 metadata
                    data = sxm.inject_id3_mutagen(
                        data,
                        self.HLS_AES_KEY,
                        sxm.current_artist,
                        sxm.current_title,
                        sxm.current_channel,
                        sxm.current_channel_id_user,
                        "http://albumart.siriusxm.com/albumart/2000/WBHITS_GDCA-112106915-001_t.jpg",
                    )
                    self.send_response(200)
                    self.send_header('Content-Type', 'audio/aac')
                    self.end_headers()
                    self.wfile.write(data)
                else:
                    self.send_response(500)
                    self.end_headers()
            else:
                self.send_response(500)
                self.end_headers()
    return SiriusHandler

# ---------------------- Main ------------------------
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='SiriusXM proxy')
    parser.add_argument('username')
    parser.add_argument('password')
    parser.add_argument('-l', '--list', required=False, action='store_true', default=False)
    parser.add_argument('-p', '--port', required=False, default=9999, type=int)
    parser.add_argument('-e', '--env',  required=False, action='store_true', default=False)
    args = vars(parser.parse_args())
    if args['env']:
        if "SXM_USER" in os.environ:
            args['username'] = os.environ.get('SXM_USER')
        if "SXM_PASS" in os.environ:
            args['password'] = os.environ.get('SXM_PASS')

    sxm = SiriusXM(args['username'], args['password'])
    if args['list']:
        channels = list(sorted(sxm.get_channels(), key=lambda x: (not x.get('isFavorite', False), int(x.get('siriusChannelNumber', 9999)))))
        
        l1 = max(len(x.get('channelId', '')) for x in channels)
        l2 = max(len(str(x.get('siriusChannelNumber', 0))) for x in channels)
        l3 = max(len(x.get('name', '')) for x in channels)
        print('{} | {} | {}'.format('ID'.ljust(l1), 'Num'.ljust(l2), 'Name'.ljust(l3)))
        for channel in channels:
            cid = channel.get('channelId', '').ljust(l1)[:l1]
            cnum = str(channel.get('siriusChannelNumber', '??')).ljust(l2)[:l2]
            cname = channel.get('name', '??').ljust(l3)[:l3]
            print('{} | {} | {}'.format(cid, cnum, cname))
    else:
        httpd = HTTPServer(('', args['port']), make_sirius_handler(sxm))
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass
        httpd.server_close()

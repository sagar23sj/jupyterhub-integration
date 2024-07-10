from jupyterhub.auth import Authenticator
from jupyterhub.spawner import LocalProcessSpawner
from Crypto.Cipher import AES
from traitlets import default
import shutil
import json
import pwd
import subprocess
import base64
import os
import time
import hmac
import hashlib

c = get_config()  #noqa

# config file path
config_file = "config.env"

# read variables from file into a dictionary
def read_file(filename):
    vars = {}
    with open(filename, "r") as file:
        for line in file:
            line = line.strip()
            if line.startswith('#') or not line:
                continue
            key, value = line.split('=', 1)
            vars[key] = value
    return vars

class MyAuthenticator(Authenticator):
    login_service = "JupyterHub Service"

    @default("auto_login")
    def _auto_login_default(self):
        return True

    async def authenticate(self,handler,data=None):
        rawd = None

        encr_token = handler.get_argument('token', default=None)
        if not encr_token:
            return None

        # Base64 decode the token
        try:
            # Read variables from the config file into a dictionary
            vars_dict = read_file(config_file)

            # access variables from the dictionary
            secret_key = vars_dict["JUPYTERHUB_SECRET_KEY"]
            if not secret_key:
                return None
            
            secret_key_bytes = str.encode(secret_key)

            hash_key = vars_dict["JUPYTERHUB_HASH_KEY"]
            if not hash_key:
                return None
            
            decrypted_data = decrypt(secret_key_bytes, hash_key, encr_token, True)

            # decoded_token = base64.b64decode(auth_state.encode()).decode()
        except Exception as e:
            self.log.error(f"Error decoding token: {e}")
            return None
        
        # Parse the decoded token as JSON
        try:
            user_data = json.loads(decrypted_data)
        except Exception as e:
            self.log.error(f"Error parsing JSON token: {e}")
            return None
        
        # Convert user data to a dictionary
        if not isinstance(user_data, dict):
            self.log.error("Invalid user data format (expected dictionary)")
            return None

        expiration_time = int(user_data.get('expiry_time'))
        time_now_seconds = int(time.time())

        if expiration_time < time_now_seconds:
            error_msg = "Token has expired " + str(expiration_time) + " < " + str(time_now_seconds)
            self.log.error(error_msg)
            return None
        
       # Do some verification and get the data here.
       # Get the data from the parameters send to your hub from the login page, say username, access_token and email. Wrap everythin neatly in a dictionary and return it.

        userdict = {"name": user_data.get('jupyterhub_user_id').replace(".", "")}
        userdict["auth_state"] = auth_state = {}
        auth_state['username'] = user_data.get('username')
        auth_state['sql_endpoint'] = user_data.get('sql_endpoint')
        auth_state['access_token'] = user_data.get('access_token')

       #return the dictionary
        return userdict

    
    async def pre_spawn_start(self, user, spawner):
        """Pass auth state data to spawner via environment variables"""
        auth_state = await user.get_auth_state()
        if not auth_state:
            # Auth state not enabled or user has no state
            return
        
        spawner.environment['USERNAME'] = auth_state['username']
        spawner.environment['SQL_ENDPOINT'] = auth_state['sql_endpoint']
        spawner.environment['ACCESS_TOKEN'] = auth_state['access_token']


def decrypt(secret_key,hash_Key, value, block_segments=False):
    # The base64 library fails if value is Unicode. Luckily, base64 is ASCII-safe.
    value = value.encode('utf-8')  # Convert to bytes
    # We add back the padding ("=") here so that the decode won't fail.
    value = base64.b64decode(value + b'=' * (4 - len(value) % 4), b'-_')

     # Extract the ciphertext and the original HMAC
    ciphertext = value[:-32]  # Everything except the last 32 bytes
    original_hmac = value[-32:]  # The last 32 bytes

    # Generate a new HMAC for the ciphertext
    new_hmac = hmac.new(hash_Key.encode(), ciphertext, hashlib.sha256).digest()

    # Compare the original HMAC with the new HMAC
    if not hmac.compare_digest(original_hmac, new_hmac):
        raise Exception("Data integrity check failed.")

    iv, value = value[:AES.block_size], value[AES.block_size:]
    if block_segments:
        # Python uses 8-bit segments by default for legacy reasons. In order to support
        # languages that encrypt using 128-bit segments, without having to use data with
        # a length divisible by 16, we need to pad and truncate the values.
        remainder = len(value) % 16
        padded_value = value + b'\0' * (16 - remainder) if remainder else value
        cipher = AES.new(secret_key, AES.MODE_CFB, iv, segment_size=128)
        # Return the decrypted string with the padding removed.
        return cipher.decrypt(padded_value)[:len(value)]
    return AES.new(secret_key, AES.MODE_CFB, iv).decrypt(value)

# Generate a random 32-byte hex key for encryption
crypt_key = os.urandom(32).hex()
os.environ["JUPYTERHUB_CRYPT_KEY"] = crypt_key

# Custom spawner class
class CustomSpawner(LocalProcessSpawner):
    async def start(self):
        # Call the original start method
        result = await super().start()
        
        # Perform post-start operations
        username = self.user.name
        source_dir = "/srv/jupyterhub/setup"
        userhome = os.path.join("/home", username)
        ipython_dir = os.path.join("/home", username, ".ipython")
        profile_dir = os.path.join(ipython_dir, "profile_default")
        startup_dir = os.path.join(profile_dir, "startup")

        if not os.path.exists(source_dir):
            raise Exception(f"Source directory {source_dir} does not exist.")

        # Ensure profile_default and startup directories exist and set permissions
        if not os.path.exists(profile_dir):
            os.makedirs(profile_dir, mode=0o755)

        os.chmod(profile_dir, 0o755)
        os.system(f"chown -R {username}:{username} {profile_dir}")

        if not os.path.exists(startup_dir):
            os.makedirs(startup_dir, mode=0o755)

        os.chmod(startup_dir, 0o755)
        os.system(f"chown -R {username}:{username} {startup_dir}")

        # Copy files, handling existing directory
        try:
            shutil.copytree(source_dir, startup_dir, dirs_exist_ok=True)
        except shutil.Error as e:
            raise Exception(f"Error copying files: {e}") from e

        # Path to the new notebook file
        notebook_path = os.path.join(userhome, 'main.ipynb')

        notebook_content = {
            "cells": [],
            "metadata": {
                "kernelspec": {
                    "name": "python3",
                    "display_name": "Python 3"
                },
                "language_info": {
                "name": "python",
                "version": "3.10.12"  # Ensure this matches the Python version you want to use
                }
            },
            "nbformat": 4,
            "nbformat_minor": 2
        }

        # Create the notebook with read, write, execute permissions
        with open(notebook_path, 'w') as notebook_file:
            json.dump(notebook_content, notebook_file)
            
        os.chmod(notebook_path, 0o777)

        # Verify the directory contents
        print("Directory contents after copying:")
        for root, dirs, files in os.walk(startup_dir):
            for name in dirs:
                print(f"DIR: {os.path.join(root, name)}")
            for name in files:
                print(f"FILE: {os.path.join(root, name)}")

        # Final permission and ownership check
        os.chmod(ipython_dir, 0o755)
        os.chmod(profile_dir, 0o755)
        os.chmod(startup_dir, 0o755)
        os.system(f"chown -R {username}:{username} {ipython_dir}")

        return result

# Just-in-time user creation with pre_spawn_hook
def pre_spawn_hook(spawner):
    username = spawner.user.name
    userhome = os.path.join("/home", username)

    #deletes all files from userhome
    if os.path.exists(userhome):
        delete_non_hidden_files(userhome)

    try:
        pwd.getpwnam(username)
    except KeyError:
        subprocess.run(["adduser", "--disabled-password", "--gecos", "", username], check=True)

# Function to delete non-hidden files in a directory
def delete_non_hidden_files(directory):
    for root, dirs, files in os.walk(directory):
        for file in files:
            # Check if the file is not hidden
            if not file.startswith('.'):
                file_path = os.path.join(root, file)
                print(f"Deleting file: {file_path}")
                os.remove(file_path)


# JupyterHub configuration
c.JupyterHub.spawner_class = CustomSpawner
c.Spawner.pre_spawn_hook = pre_spawn_hook
c.JupyterHubSpawner.user_options_form_url = ""
c.Authenticator.refresh_pre_spawn = True
c.Authenticator.allow_all = True

# c.JupyterHub.singleuser_app = 'notebook.notebookapp.NotebookApp'
c.Spawner.default_url = '/notebooks/main.ipynb'

##Just-in-time user creation with pre_spawn_hook
# def pre_spawn_hook(spawner):
#     username = spawner.user.name
#     try:
#         pwd.getpwnam(username)
#     except KeyError:
#         subprocess.run(["adduser", "--disabled-password", "--gecos", "", username], check=True)

#     source_dir = "/srv/jupyterhub/setup"
#     ipython_dir = os.path.join("/home", username, ".ipython")
#     dest_dir = os.path.join("/home",username, ".ipython/profile_default/startup")

#     if not os.path.exists(source_dir):
#         raise Exception(f"Source directory {source_dir} does not exist.")


#     # Ensure .ipython directory exists and is writable
#     if not os.path.exists(ipython_dir):
#         os.makedirs(ipython_dir, mode=0o755)

#     os.chmod(ipython_dir, 0o755)
    
#     # Ensure profile_default/startup directory exists and set permissions
#     if not os.path.exists(dest_dir):
#         os.makedirs(dest_dir, mode=0o755)

#     os.chmod(dest_dir, 0o755)

#     if not os.path.exists(dest_dir):
#         raise Exception(f"Destination directory {dest_dir} does not exist.")


#     # Copy files, handling existing directory
#     try:
#         shutil.copytree(source_dir, dest_dir, dirs_exist_ok=True)
#     except shutil.Error as e:
#         raise Exception(f"Error copying files: {e}") from e


# c.Spawner.pre_spawn_hook = pre_spawn_hook

## Enable persisting auth_state (if available).
#  
#          auth_state will be encrypted and stored in the Hub's database.
#          This can include things like authentication tokens, etc.
#          to be passed to Spawners as environment variables.
#  
#          Encrypting auth_state requires the cryptography package.
#  
#          Additionally, the JUPYTERHUB_CRYPT_KEY environment variable must
#          contain one (or more, separated by ;) 32B encryption keys.
#          These can be either base64 or hex-encoded.
#  
#          If encryption is unavailable, auth_state cannot be persisted.
#  
#          New in JupyterHub 0.8
#  Default: False
c.Authenticator.enable_auth_state = True

## Automatically begin the login process
#  
#          rather than starting with a "Login with..." link at `/hub/login`
#  
#          To work, `.login_url()` must give a URL other than the default `/hub/login`,
#          such as an oauth handler or another automatic login handler,
#          registered with `.get_handlers()`.
#  
#          .. versionadded:: 0.8
#  Default: False

c.JupyterHub.authenticator_class = MyAuthenticator

## Specify path to a logo image to override the Jupyter logo in the banner.
#  Default: ''
c.JupyterHub.logo_file = 'datapelago-logo.png'

## Shuts down all user servers on logout
#  Default: False
c.JupyterHub.shutdown_on_logout = True

#------------------------------------------------------------------------------
# Application(SingletonConfigurable) configuration
#------------------------------------------------------------------------------
## This is an application.

## The date format used by logging formatters for %(asctime)s
#  Default: '%Y-%m-%d %H:%M:%S'
c.Application.log_datefmt = '%Y-%m-%d %H:%M:%S'

## The Logging format template
#  Default: '[%(name)s]%(highlevel)s %(message)s'
c.Application.log_format = '[%(name)s]%(highlevel)s %(message)s'

## Set the log level by value or name.
#  Choices: any of [0, 10, 20, 30, 40, 50, 'DEBUG', 'INFO', 'WARN', 'ERROR', 'CRITICAL']
#  Default: 30
c.Application.log_level = 30

## The public facing URL of the whole JupyterHub application.
#  
#          This is the address on which the proxy will bind.
#          Sets protocol, ip, base_url
#  Default: 'http://:8000'
# c.JupyterHub.bind_url = 'http://:8000'

#------------------------------------------------------------------------------
# JupyterHub(Application) configuration
#------------------------------------------------------------------------------
## An Application for starting a Multi-User Jupyter Notebook server.

## Maximum number of concurrent servers that can be active at a time.
#  
#  Setting this can limit the total resources your users can consume.
#  
#  An active server is any server that's not fully stopped. It is considered
#  active from the time it has been requested until the time that it has
#  completely stopped.
#  
#  If this many user servers are active, users will not be able to launch new
#  servers until a server is shutdown. Spawn requests will be rejected with a 429
#  error asking them to try again.
#  
#  If set to 0, no limit is enforced.
#  Default: 0
# c.JupyterHub.active_server_limit = 0

## Duration (in seconds) to determine the number of active users.
#  Default: 1800
# c.JupyterHub.active_user_window = 1800

## Resolution (in seconds) for updating activity
#  
#  If activity is registered that is less than activity_resolution seconds more
#  recent than the current value, the new value will be ignored.
#  
#  This avoids too many writes to the Hub database.
#  Default: 30
# c.JupyterHub.activity_resolution = 30


## DEPRECATED since version 0.7.2, use Authenticator.admin_users instead.
#  Default: set()
# c.JupyterHub.admin_users = set()

## Allow named single-user servers per user
#  Default: False
# c.JupyterHub.allow_named_servers = False

## Answer yes to any questions (e.g. confirm overwrite)
#  Default: False
# c.JupyterHub.answer_yes = False

## The default amount of records returned by a paginated endpoint
#  Default: 50
# c.JupyterHub.api_page_default_limit = 50

## The maximum amount of records that can be returned at once
#  Default: 200
# c.JupyterHub.api_page_max_limit = 200

## PENDING DEPRECATION: consider using services
#  
#          Dict of token:username to be loaded into the database.
#  
#          Allows ahead-of-time generation of API tokens for use by externally managed services,
#          which authenticate as JupyterHub users.
#  
#          Consider using services for general services that talk to the
#  JupyterHub API.
#  Default: {}
# c.JupyterHub.api_tokens = {}

## Authentication for prometheus metrics
#  Default: True
# c.JupyterHub.authenticate_prometheus = True

## Whether to shutdown the proxy when the Hub shuts down.
#  
#          Disable if you want to be able to teardown the Hub while leaving the
#  proxy running.
#  
#          Only valid if the proxy was starting by the Hub process.
#  
#          If both this and cleanup_servers are False, sending SIGINT to the Hub will
#          only shutdown the Hub, leaving everything else running.
#  
#          The Hub should be able to resume from database state.
#  Default: True
# c.JupyterHub.cleanup_proxy = True

## Whether to shutdown single-user servers when the Hub shuts down.
#  
#          Disable if you want to be able to teardown the Hub while leaving the
#  single-user servers running.
#  
#          If both this and cleanup_proxy are False, sending SIGINT to the Hub will
#          only shutdown the Hub, leaving everything else running.
#  
#          The Hub should be able to resume from database state.
#  Default: True
# c.JupyterHub.cleanup_servers = True

## Maximum number of concurrent users that can be spawning at a time.
#  
#  Spawning lots of servers at the same time can cause performance problems for
#  the Hub or the underlying spawning system. Set this limit to prevent bursts of
#  logins from attempting to spawn too many servers at the same time.
#  
#  This does not limit the number of total running servers. See
#  active_server_limit for that.
#  
#  If more than this many users attempt to spawn at a time, their requests will
#  be rejected with a 429 error asking them to try again. Users will have to wait
#  for some of the spawning services to finish starting before they can start
#  their own.
#  
#  If set to 0, no limit is enforced.
#  Default: 100
# c.JupyterHub.concurrent_spawn_limit = 100

## The config file to load
#  Default: 'jupyterhub_config.py'
# c.JupyterHub.config_file = 'jupyterhub_config.py'


## Enable `__Host-` prefix on authentication cookies.
#  
#          The `__Host-` prefix on JupyterHub cookies provides further
#          protection against cookie tossing when untrusted servers
#          may control subdomains of your jupyterhub deployment.
#  
#          _However_, it also requires that cookies be set on the path `/`,
#          which means they are shared by all JupyterHub components,
#          so a compromised server component will have access to _all_ JupyterHub-related
#          cookies of the visiting browser.
#          It is recommended to only combine `__Host-` cookies with per-user domains.
#  
#          .. versionadded:: 4.1
#  Default: False
# c.JupyterHub.cookie_host_prefix_enabled = False

## Number of days for a login cookie to be valid.
#          Default is two weeks.
#  Default: 14
# c.JupyterHub.cookie_max_age_days = 14

## The cookie secret to use to encrypt cookies.
#  
#          Loaded from the JPY_COOKIE_SECRET env variable by default.
#  
#          Should be exactly 256 bits (32 bytes).
#  Default: traitlets.Undefined
# c.JupyterHub.cookie_secret = traitlets.Undefined

## File in which to store the cookie secret.
#  Default: 'jupyterhub_cookie_secret'
# c.JupyterHub.cookie_secret_file = 'jupyterhub_cookie_secret'

## Custom scopes to define.
#  
#          For use when defining custom roles,
#          to grant users granular permissions
#  
#          All custom scopes must have a description,
#          and must start with the prefix `custom:`.
#  
#          For example::
#  
#              custom_scopes = {
#                  "custom:jupyter_server:read": {
#                      "description": "read-only access to a single-user server",
#                  },
#              }
#  Default: {}
# c.JupyterHub.custom_scopes = {}

## The location of jupyterhub data files (e.g. /usr/local/share/jupyterhub)
#  Default: '/usr/local/share/jupyterhub'
# c.JupyterHub.data_files_path = '/usr/local/share/jupyterhub'

## Include any kwargs to pass to the database connection.
#          See sqlalchemy.create_engine for details.
#  Default: {}
# c.JupyterHub.db_kwargs = {}

## url for the database. e.g. `sqlite:///jupyterhub.sqlite`
#  Default: 'sqlite:///jupyterhub.sqlite'
# c.JupyterHub.db_url = 'sqlite:///jupyterhub.sqlite'

## log all database transactions. This has A LOT of output
#  Default: False
# c.JupyterHub.debug_db = False


## If named servers are enabled, default name of server to spawn or open when no
#  server is specified, e.g. by user-redirect.
#  
#  Note: This has no effect if named servers are not enabled, and does _not_
#  change the existence or behavior of the default server named `''` (the empty
#  string). This only affects which named server is launched when no server is
#  specified, e.g. by links to `/hub/user-redirect/lab/tree/mynotebook.ipynb`.
#  Default: ''
# c.JupyterHub.default_server_name = ''

## The default URL for users when they arrive (e.g. when user directs to "/")
#  
#  By default, redirects users to their own server.
#  
#  Can be a Unicode string (e.g. '/hub/home') or a callable based on the handler
#  object:
#  
#  ::
#  
#      def default_url_fn(handler):
#          user = handler.current_user
#          if user and user.admin:
#              return '/hub/admin'
#          return '/hub/home'
#  
#      c.JupyterHub.default_url = default_url_fn
#  Default: traitlets.Undefined
# c.JupyterHub.default_url = traitlets.Undefined

## Dict authority:dict(files). Specify the key, cert, and/or
#          ca file for an authority. This is useful for externally managed
#          proxies that wish to use internal_ssl.
#  
#          The files dict has this format (you must specify at least a cert)::
#  
#              {
#                  'key': '/path/to/key.key',
#                  'cert': '/path/to/cert.crt',
#                  'ca': '/path/to/ca.crt'
#              }
#  
#          The authorities you can override: 'hub-ca', 'notebooks-ca',
#          'proxy-api-ca', 'proxy-client-ca', and 'services-ca'.
#  
#          Use with internal_ssl
#  Default: {}
# c.JupyterHub.external_ssl_authorities = {}



## Alternate header to use as the Host (e.g., X-Forwarded-Host)
#          when determining whether a request is cross-origin
#  
#          This may be useful when JupyterHub is running behind a proxy that rewrites
#          the Host header.
#  Default: ''
# c.JupyterHub.forwarded_host_header = ''

## Generate certs used for internal ssl
#  Default: False
# c.JupyterHub.generate_certs = False

## Generate default config file
#  Default: False
# c.JupyterHub.generate_config = False

## The URL on which the Hub will listen. This is a private URL for internal
#  communication. Typically set in combination with hub_connect_url. If a unix
#  socket, hub_connect_url **must** also be set.
#  
#  For example:
#  
#      "http://127.0.0.1:8081"
#      "unix+http://%2Fsrv%2Fjupyterhub%2Fjupyterhub.sock"
#  
#  .. versionadded:: 0.9
#  Default: ''
# c.JupyterHub.hub_bind_url = ''

## The ip or hostname for proxies and spawners to use
#          for connecting to the Hub.
#  
#          Use when the bind address (`hub_ip`) is 0.0.0.0, :: or otherwise different
#          from the connect address.
#  
#          Default: when `hub_ip` is 0.0.0.0 or ::, use `socket.gethostname()`,
#  otherwise use `hub_ip`.
#  
#          Note: Some spawners or proxy implementations might not support hostnames. Check your
#          spawner or proxy documentation to see if they have extra requirements.
#  
#          .. versionadded:: 0.8
#  Default: ''
# c.JupyterHub.hub_connect_ip = ''


## The ip address for the Hub process to *bind* to.
#  
#          By default, the hub listens on localhost only. This address must be accessible from
#          the proxy and user servers. You may need to set this to a public ip or '' for all
#          interfaces if the proxy or user servers are in containers or on a different host.
#  
#          See `hub_connect_ip` for cases where the bind and connect address should differ,
#          or `hub_bind_url` for setting the full bind URL.
#  Default: '127.0.0.1'
# c.JupyterHub.hub_ip = '127.0.0.1'

## The internal port for the Hub process.
#  
#          This is the internal port of the hub itself. It should never be accessed directly.
#          See JupyterHub.port for the public port to use when accessing jupyterhub.
#          It is rare that this port should be set except in cases of port conflict.
#  
#          See also `hub_ip` for the ip and `hub_bind_url` for setting the full
#  bind URL.
#  Default: 8081
# c.JupyterHub.hub_port = 8081

## The routing prefix for the Hub itself.
#  
#  Override to send only a subset of traffic to the Hub. Default is to use the
#  Hub as the default route for all requests.
#  
#  This is necessary for normal jupyterhub operation, as the Hub must receive
#  requests for e.g. `/user/:name` when the user's server is not running.
#  
#  However, some deployments using only the JupyterHub API may want to handle
#  these events themselves, in which case they can register their own default
#  target with the proxy and set e.g. `hub_routespec = /hub/` to serve only the
#  hub's own pages, or even `/hub/api/` for api-only operation.
#  
#  Note: hub_routespec must include the base_url, if any.
#  
#  .. versionadded:: 1.4
#  Default: '/'
# c.JupyterHub.hub_routespec = '/'

## Trigger implicit spawns after this many seconds.
#  
#          When a user visits a URL for a server that's not running,
#          they are shown a page indicating that the requested server
#          is not running with a button to spawn the server.
#  
#          Setting this to a positive value will redirect the user
#          after this many seconds, effectively clicking this button
#          automatically for the users,
#          automatically beginning the spawn process.
#  
#          Warning: this can result in errors and surprising behavior
#          when sharing access URLs to actual servers,
#          since the wrong server is likely to be started.
#  Default: 0
# c.JupyterHub.implicit_spawn_seconds = 0

## Timeout (in seconds) to wait for spawners to initialize
#  
#  Checking if spawners are healthy can take a long time if many spawners are
#  active at hub start time.
#  
#  If it takes longer than this timeout to check, init_spawner will be left to
#  complete in the background and the http server is allowed to start.
#  
#  A timeout of -1 means wait forever, which can mean a slow startup of the Hub
#  but ensures that the Hub is fully consistent by the time it starts responding
#  to requests. This matches the behavior of jupyterhub 1.0.
#  
#  .. versionadded: 1.1.0
#  Default: 10
# c.JupyterHub.init_spawners_timeout = 10

## The location to store certificates automatically created by
#          JupyterHub.
#  
#          Use with internal_ssl
#  Default: 'internal-ssl'
# c.JupyterHub.internal_certs_location = 'internal-ssl'

## Enable SSL for all internal communication
#  
#          This enables end-to-end encryption between all JupyterHub components.
#          JupyterHub will automatically create the necessary certificate
#          authority and sign notebook certificates as they're created.
#  Default: False
# c.JupyterHub.internal_ssl = False

## The public facing ip of the whole JupyterHub application
#          (specifically referred to as the proxy).
#  
#          This is the address on which the proxy will listen. The default is to
#          listen on all interfaces. This is the only address through which JupyterHub
#          should be accessed by users.
#  
#          .. deprecated: 0.9
#              Use JupyterHub.bind_url
#  Default: ''
# c.JupyterHub.ip = ''


## Interval (in seconds) at which to update last-activity timestamps.
#  Default: 300
# c.JupyterHub.last_activity_interval = 300


## Maximum number of concurrent named servers that can be created by a user at a
#  time.
#  
#  Setting this can limit the total resources a user can consume.
#  
#  If set to 0, no limit is enforced.
#  
#  Can be an integer or a callable/awaitable based on the handler object:
#  
#  ::
#  
#      def named_server_limit_per_user_fn(handler):
#          user = handler.current_user
#          if user and user.admin:
#              return 0
#          return 5
#  
#      c.JupyterHub.named_server_limit_per_user = named_server_limit_per_user_fn
#  Default: 0
# c.JupyterHub.named_server_limit_per_user = 0

## Expiry (in seconds) of OAuth access tokens.
#  
#          The default is to expire when the cookie storing them expires,
#          according to `cookie_max_age_days` config.
#  
#          These are the tokens stored in cookies when you visit
#          a single-user server or service.
#          When they expire, you must re-authenticate with the Hub,
#          even if your Hub authentication is still valid.
#          If your Hub authentication is valid,
#          logging in may be a transparent redirect as you refresh the page.
#  
#          This does not affect JupyterHub API tokens in general,
#          which do not expire by default.
#          Only tokens issued during the oauth flow
#          accessing services and single-user servers are affected.
#  
#          .. versionadded:: 1.4
#              OAuth token expires_in was not previously configurable.
#          .. versionchanged:: 1.4
#              Default now uses cookie_max_age_days so that oauth tokens
#              which are generally stored in cookies,
#              expire when the cookies storing them expire.
#              Previously, it was one hour.
#  Default: 0
# c.JupyterHub.oauth_token_expires_in = 0

## File to write PID
#          Useful for daemonizing JupyterHub.
#  Default: ''
# c.JupyterHub.pid_file = ''

## The public facing port of the proxy.
#  
#          This is the port on which the proxy will listen.
#          This is the only port through which JupyterHub
#          should be accessed by users.
#  
#          .. deprecated: 0.9
#              Use JupyterHub.bind_url
#  Default: 8000
# c.JupyterHub.port = 8000

## The class to use for configuring the JupyterHub proxy.
#  
#          Should be a subclass of :class:`jupyterhub.proxy.Proxy`.
#  
#          .. versionchanged:: 1.0
#              proxies may be registered via entry points,
#              e.g. `c.JupyterHub.proxy_class = 'traefik'`
#  
#  Currently installed: 
#    - configurable-http-proxy: jupyterhub.proxy.ConfigurableHTTPProxy
#    - default: jupyterhub.proxy.ConfigurableHTTPProxy
#  Default: 'jupyterhub.proxy.ConfigurableHTTPProxy'
# c.JupyterHub.proxy_class = 'jupyterhub.proxy.ConfigurableHTTPProxy'

## Recreate all certificates used within JupyterHub on restart.
#  
#          Note: enabling this feature requires restarting all notebook servers.
#  
#          Use with internal_ssl
#  Default: False
# c.JupyterHub.recreate_internal_certs = False

## Redirect user to server (if running), instead of control panel.
#  Default: True
# c.JupyterHub.redirect_to_server = True

## Purge and reset the database.
#  Default: False
# c.JupyterHub.reset_db = False

## Interval (in seconds) at which to check connectivity of services with web
#  endpoints.
#  Default: 60
# c.JupyterHub.service_check_interval = 60

## Dict of token:servicename to be loaded into the database.
#  
#          Allows ahead-of-time generation of API tokens for use by externally
#  managed services.
#  Default: {}
# c.JupyterHub.service_tokens = {}

## The class to use for spawning single-user servers.
#  
#          Should be a subclass of :class:`jupyterhub.spawner.Spawner`.
#  
#          .. versionchanged:: 1.0
#              spawners may be registered via entry points,
#              e.g. `c.JupyterHub.spawner_class = 'localprocess'`
#  
#  Currently installed: 
#    - default: jupyterhub.spawner.LocalProcessSpawner
#    - localprocess: jupyterhub.spawner.LocalProcessSpawner
#    - simple: jupyterhub.spawner.SimpleLocalProcessSpawner
#  Default: 'jupyterhub.spawner.LocalProcessSpawner'
# c.JupyterHub.spawner_class = 'jupyterhub.spawner.LocalProcessSpawner'

## Path to SSL certificate file for the public facing interface of the proxy
#  
#          When setting this, you should also set ssl_key
#  Default: ''
# c.JupyterHub.ssl_cert = ''

## Path to SSL key file for the public facing interface of the proxy
#  
#          When setting this, you should also set ssl_cert
#  Default: ''
# c.JupyterHub.ssl_key = ''

## Run single-user servers on subdomains of this host.
#  
#          This should be the full `https://hub.domain.tld[:port]`.
#  
#          Provides additional cross-site protections for javascript served by
#  single-user servers.
#  
#          Requires `<username>.hub.domain.tld` to resolve to the same host as
#  `hub.domain.tld`.
#  
#          In general, this is most easily achieved with wildcard DNS.
#  
#          When using SSL (i.e. always) this also requires a wildcard SSL
#  certificate.
#  Default: ''
# c.JupyterHub.subdomain_host = ''


## Trust user-provided tokens (via JupyterHub.service_tokens)
#          to have good entropy.
#  
#          If you are not inserting additional tokens via configuration file,
#          this flag has no effect.
#  
#          In JupyterHub 0.8, internally generated tokens do not
#          pass through additional hashing because the hashing is costly
#          and does not increase the entropy of already-good UUIDs.
#  
#          User-provided tokens, on the other hand, are not trusted to have good entropy by default,
#          and are passed through many rounds of hashing to stretch the entropy of the key
#          (i.e. user-provided tokens are treated as passwords instead of random keys).
#          These keys are more costly to check.
#  
#          If your inserted tokens are generated by a good-quality mechanism,
#          e.g. `openssl rand -hex 32`, then you can set this flag to True
#          to reduce the cost of checking authentication tokens.
#  Default: False
# c.JupyterHub.trust_user_provided_tokens = False

## Upgrade the database automatically on start.
#  
#          Only safe if database is regularly backed up.
#          Only SQLite databases will be backed up to a local file automatically.
#  Default: False
# c.JupyterHub.upgrade_db = False

## Return 503 rather than 424 when request comes in for a non-running server.
#  
#  Prior to JupyterHub 2.0, we returned a 503 when any request came in for a user
#  server that was currently not running. By default, JupyterHub 2.0 will return
#  a 424 - this makes operational metric dashboards more useful.
#  
#  JupyterLab < 3.2 expected the 503 to know if the user server is no longer
#  running, and prompted the user to start their server. Set this config to true
#  to retain the old behavior, so JupyterLab < 3.2 can continue to show the
#  appropriate UI when the user server is stopped.
#  
#  This option will be removed in a future release.
#  Default: False
# c.JupyterHub.use_legacy_stopped_server_status_code = False

## Callable to affect behavior of /user-redirect/
#  
#  Receives 4 parameters: 1. path - URL path that was provided after /user-
#  redirect/ 2. request - A Tornado HTTPServerRequest representing the current
#  request. 3. user - The currently authenticated user. 4. base_url - The
#  base_url of the current hub, for relative redirects
#  
#  It should return the new URL to redirect to, or None to preserve current
#  behavior.
#  Default: None
# c.JupyterHub.user_redirect_hook = None

#------------------------------------------------------------------------------
# Spawner(LoggingConfigurable) configuration
#------------------------------------------------------------------------------
## Base class for spawning single-user notebook servers.
#  
#      Subclass this, and override the following methods:
#  
#      - load_state
#      - get_state
#      - start
#      - stop
#      - poll
#  
#      As JupyterHub supports multiple users, an instance of the Spawner subclass
#      is created for each user. If there are 20 JupyterHub users, there will be 20
#      instances of the subclass.

## Maximum number of consecutive failures to allow before shutting down
#  JupyterHub.
#  
#  This helps JupyterHub recover from a certain class of problem preventing
#  launch in contexts where the Hub is automatically restarted (e.g. systemd,
#  docker, kubernetes).
#  
#  A limit of 0 means no limit and consecutive failures will not be tracked.
#  Default: 0
# c.Spawner.consecutive_failure_limit = 0

## Minimum number of cpu-cores a single-user notebook server is guaranteed to
#  have available.
#  
#  If this value is set to 0.5, allows use of 50% of one CPU. If this value is
#  set to 2, allows use of up to 2 CPUs.
#  
#  **This is a configuration setting. Your spawner must implement support for the
#  limit to work.** The default spawner, `LocalProcessSpawner`, does **not**
#  implement this support. A custom spawner **must** add support for this setting
#  for it to be enforced.
#  Default: None
# c.Spawner.cpu_guarantee = None

## Maximum number of cpu-cores a single-user notebook server is allowed to use.
#  
#  If this value is set to 0.5, allows use of 50% of one CPU. If this value is
#  set to 2, allows use of up to 2 CPUs.
#  
#  The single-user notebook server will never be scheduled by the kernel to use
#  more cpu-cores than this. There is no guarantee that it can access this many
#  cpu-cores.
#  
#  **This is a configuration setting. Your spawner must implement support for the
#  limit to work.** The default spawner, `LocalProcessSpawner`, does **not**
#  implement this support. A custom spawner **must** add support for this setting
#  for it to be enforced.
#  Default: None
# c.Spawner.cpu_limit = None

## Enable debug-logging of the single-user server
#  Default: False
# c.Spawner.debug = False

## Extra environment variables to set for the single-user server's process.
#  
#  Environment variables that end up in the single-user server's process come from 3 sources:
#    - This `environment` configurable
#    - The JupyterHub process' environment variables that are listed in `env_keep`
#    - Variables to establish contact between the single-user notebook and the hub (such as JUPYTERHUB_API_TOKEN)
#  
#  The `environment` configurable should be set by JupyterHub administrators to
#  add installation specific environment variables. It is a dict where the key is
#  the name of the environment variable, and the value can be a string or a
#  callable. If it is a callable, it will be called with one parameter (the
#  spawner instance), and should return a string fairly quickly (no blocking
#  operations please!).
#  
#  Note that the spawner class' interface is not guaranteed to be exactly same
#  across upgrades, so if you are using the callable take care to verify it
#  continues to work after upgrades!
#  
#  .. versionchanged:: 1.2
#      environment from this configuration has highest priority,
#      allowing override of 'default' env variables,
#      such as JUPYTERHUB_API_URL.
#  Default: {}
# c.Spawner.environment = {}

## Timeout (in seconds) before giving up on a spawned HTTP server
#  
#  Once a server has successfully been spawned, this is the amount of time we
#  wait before assuming that the server is unable to accept connections.
#  Default: 30
# c.Spawner.http_timeout = 30

## The IP address (or hostname) the single-user server should listen on.
#  
#  Usually either '127.0.0.1' (default) or '0.0.0.0'.
#  
#  The JupyterHub proxy implementation should be able to send packets to this
#  interface.
#  
#  Subclasses which launch remotely or in containers should override the default
#  to '0.0.0.0'.
#  
#  .. versionchanged:: 2.0
#      Default changed to '127.0.0.1', from ''.
#      In most cases, this does not result in a change in behavior,
#      as '' was interpreted as 'unspecified',
#      which used the subprocesses' own default, itself usually '127.0.0.1'.
#  Default: '127.0.0.1'
# c.Spawner.ip = '127.0.0.1'


## Interval (in seconds) on which to poll the spawner for single-user server's
#  status.
#  
#  At every poll interval, each spawner's `.poll` method is called, which checks
#  if the single-user server is still running. If it isn't running, then
#  JupyterHub modifies its own state accordingly and removes appropriate routes
#  from the configurable proxy.
#  Default: 30
# c.Spawner.poll_interval = 30

#------------------------------------------------------------------------------
# Authenticator(LoggingConfigurable) configuration
#------------------------------------------------------------------------------
## Base class for implementing an authentication provider for JupyterHub

## Delete any users from the database that do not pass validation
#  
#          When JupyterHub starts, `.add_user` will be called
#          on each user in the database to verify that all users are still valid.
#  
#          If `delete_invalid_users` is True,
#          any users that do not pass validation will be deleted from the database.
#          Use this if users might be deleted from an external system,
#          such as local user accounts.
#  
#          If False (default), invalid users remain in the Hub's database
#          and a warning will be issued.
#          This is the default to avoid data loss due to config changes.
#  Default: False
# c.Authenticator.delete_invalid_users = False



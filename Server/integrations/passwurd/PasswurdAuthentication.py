# Author: Madhumita Subramaniam

from org.gluu.oxauth.client import RegisterClient
from org.gluu.oxauth.client import RegisterRequest
from org.gluu.oxauth.client import RegisterResponse
from org.gluu.oxauth.model.common import GrantType
from org.gluu.oxauth.model.register import ApplicationType
from org.gluu.oxauth.model.util import StringUtils
from org.gluu.oxauth.model.common import User, WebKeyStorage
from org.gluu.oxauth.model.configuration import AppConfiguration
from org.gluu.oxauth.model.crypto import OxAuthCryptoProvider
from org.gluu.oxauth.model.crypto.signature import SignatureAlgorithm
from org.oxauth.persistence.model.configuration import GluuConfiguration
from org.gluu.oxauth.security import Identity
from org.gluu.oxauth.util import ServerUtil
from org.gluu.oxauth.service import AuthenticationService, UserService
from org.gluu.oxauth.service.custom import CustomScriptService
from org.gluu.model.custom.script import CustomScriptType
from org.gluu.model.custom.script.type.auth import PersonAuthenticationType
from org.gluu.model import SimpleCustomProperty
from org.gluu.persist import PersistenceEntryManager
from org.gluu.service.cdi.util import CdiUtil
from org.gluu.util import StringHelper
from org.gluu.jsf2.message import FacesMessages
from org.gluu.oxauth.service.net import HttpService
from org.json import JSONObject
from org.json import JSONArray

from java.lang import System
from java.lang import String
from java.util import UUID
from java.net import URLDecoder, URLEncoder
from java.util import Arrays, ArrayList, Collections, HashMap
from javax.faces.application import FacesMessage
from javax.servlet.http import Cookie
from javax.faces.context import FacesContext

import random

import base64
import ssl
import json

try:
    import json
except ImportError:
    import simplejson as json
import sys

class PersonAuthentication(PersonAuthenticationType):
    def __init__(self, currentTimeMillis):
        self.currentTimeMillis = currentTimeMillis
        self.ACR_SG = "super_gluu"
        self.PREV_LOGIN_SETTING = "prevLoginsCookieSettings"
        
        self.modulePrefix = "passwurd-external_"

    def init(self, customScript, configurationAttributes):    	
        print "Passwurd. init called"
        
        if not configurationAttributes.containsKey("AS_ENDPOINT"):
            print "Passwurd. Initialization. Property AS_ENDPOINT is mandatory"
            return False
        self.AS_ENDPOINT = configurationAttributes.get("AS_ENDPOINT").getValue2()
        
        if not configurationAttributes.containsKey("AS_SSA"):
            print "Passwurd. Initialization. Property AS_SSA is mandatory"
            return False
        self.AS_SSA = configurationAttributes.get("AS_SSA").getValue2()
        
        if not configurationAttributes.containsKey("AS_CLIENT_ID"):
            print "Passwurd. Initialization. Property AS_CLIENT_ID is mandatory"
            return False
        self.AS_CLIENT_ID = configurationAttributes.get("AS_CLIENT_ID").getValue2()
        
        
        if not configurationAttributes.containsKey("AS_CLIENT_SECRET"):
            print "Passwurd. Initialization. Property AS_CLIENT_SECRET is mandatory"
            return False
        self.AS_CLIENT_SECRET = configurationAttributes.get("AS_CLIENT_SECRET").getValue2()
        
        if not configurationAttributes.containsKey("AS_REDIRECT_URI"):
            print "Passwurd. Initialization. Property AS_REDIRECT_URI is mandatory"
            return False
        self.AS_REDIRECT_URI = configurationAttributes.get("AS_REDIRECT_URI").getValue2()
        
          
        # JWKS used to sign the SSA 
        if not configurationAttributes.containsKey("PORTAL_JWKS"):
            print "Passwurd. Initialization. Property PORTAL_JWKS is mandatory"
            return False
        self.PORTAL_JWKS = configurationAttributes.get("PORTAL_JWKS").getValue2()
        
        
        # KEY A 
        if not configurationAttributes.containsKey("PASSWURD_KEY_A_KEYSTORE"):
            print "Passwurd. Initialization. Property PASSWURD_KEY_A_KEYSTORE is mandatory"
            return False
        self.PASSWURD_KEY_A_KEYSTORE = configurationAttributes.get("PASSWURD_KEY_A_KEYSTORE").getValue2()
        
        # KEY A 
        if not configurationAttributes.containsKey("PASSWURD_KEY_A_PASSWORD"):
            print "Passwurd. Initialization. Property PASSWURD_KEY_A_PASSWORD is mandatory"
            return False
        self.PASSWURD_KEY_A_PASSWORD = configurationAttributes.get("PASSWURD_KEY_A_PASSWORD").getValue2()
        
        # KEY A 
        if not configurationAttributes.containsKey("PASSWURD_API_URL"):
            print "Passwurd. Initialization. Property PASSWURD_API_URL is mandatory"
            return False
        self.PASSWURD_API_URL = configurationAttributes.get("PASSWURD_API_URL").getValue2()
        
        
        
        self.authenticators = {}
        self.uid_attr = self.getLocalPrimaryKey()
        
        self.prevLoginsSettings = self.computePrevLoginsSettings(configurationAttributes.get(self.PREV_LOGIN_SETTING))
        custScriptService = CdiUtil.bean(CustomScriptService)
        self.scriptsList = custScriptService.findCustomScripts(Collections.singletonList(CustomScriptType.PERSON_AUTHENTICATION), "oxConfigurationProperty", "displayName", "oxEnabled")
        dynamicMethods = self.computeMethods(configurationAttributes.get("snd_step_methods"), self.scriptsList)

        if len(dynamicMethods) > 0:
            
            for acr in dynamicMethods:
                moduleName = self.modulePrefix + acr
                try:
                    external = __import__(moduleName, globals(), locals(), ["PersonAuthentication"], -1)
                    module = external.PersonAuthentication(self.currentTimeMillis)

                    print "Passwurd. init. Got dynamic module for acr %s" % acr
                    configAttrs = self.getConfigurationAttributes(acr, self.scriptsList)
                    
                    if acr == self.ACR_SG:
                        application_id = configurationAttributes.get("supergluu_app_id").getValue2()
                        configAttrs.put("application_id", SimpleCustomProperty("application_id", application_id))

                    if module.init(None, configAttrs):
                        module.configAttrs = configAttrs
                        self.authenticators[acr] = module
                    else:
                        print "Passwurd. init. Call to init in module '%s' returned False" % moduleName
                except:
                    print "Passwurd. init. Failed to load module %s" % moduleName
                    print "Exception: ", sys.exc_info()[1]
        else:
            print "Passwurd. init. Not enough custom scripts enabled. Check config property 'snd_step_methods'"
            return False
        
        self.cryptoProvider = OxAuthCryptoProvider(self.PASSWURD_KEY_A_KEYSTORE, self.PASSWURD_KEY_A_PASSWORD, None)
        # HTTPS client
        httpService = CdiUtil.bean(HttpService)
        self.http_client = httpService.getHttpsClient()

        # upon client creation, this value is populated, after that this call will not go through in subsequent script restart
        if StringHelper.isEmptyString(self.AS_CLIENT_ID):
            success = self.createClientPy(customScript)
            if not success:
                print "Passwurd. Init. Client Registration failed."
                return False

        print "Passwurd. init. Initialized successfully"
        return True

    def destroy(self, configurationAttributes):
        return True

    def getApiVersion(self):
        return 11

    def getAuthenticationMethodClaims(self, configurationAttributes):
        return None

    def isValidAuthenticationMethod(self, usageType, configurationAttributes):
        return True

    def getAlternativeAuthenticationMethod(self, usageType, configurationAttributes):
        return None

    def authenticate(self, configurationAttributes, requestParameters, step):
        print "Passwurd. AUTHENTICATE  for step %d" % step

        userService = CdiUtil.bean(UserService)
        authenticationService = CdiUtil.bean(AuthenticationService)
        identity = CdiUtil.bean(Identity)

        if step == 1:
            user_name = ServerUtil.getFirstValue(requestParameters, "username")
            k_username = ServerUtil.getFirstValue(requestParameters, "k_username")
            print "username -%s" % user_name 
            print "- k_username %s" % k_username
            if StringHelper.isNotEmptyString(user_name):
                foundUser = userService.getUserByAttribute(self.uid_attr, user_name)
                if foundUser == None:
                    print "Passwurd. Unknown username '%s'" % user_name
                    return False
                else:
                    logged_in = authenticationService.authenticate(user_name)
                    if (logged_in is True):
                        identity.setWorkingParameter("k_username", k_username)
                        if foundUser.getAttribute("userPassword") is None:
                            identity.setWorkingParameter("passwordNotSaved", "true")
                        else:
                            identity.setWorkingParameter("passwordNotSaved", "false")
                            
                        availMethods = self.getAvailMethodsUser(foundUser)
                        if availMethods.size() > 0:
                            acr = availMethods.get(0)
                            print "Passwurd. Method to try in incase of 2fa step will be: %s" % acr
                            identity.setWorkingParameter("ACR", acr)
                    print "Logged In : %s" % logged_in
                    return logged_in
        elif(step == 2):
            user = authenticationService.getAuthenticatedUser()
            username =  user.getUserId()
            if user == None:
                print "Passwurd. authenticate for step 2. Cannot retrieve logged user"
                return False
        
            elif(CdiUtil.bean(Identity).getWorkingParameter("passwordScanFailed") == "true"):
                result_2fa = self.authenticate2FAStep(requestParameters, user, step)
                if result_2fa == True:
                    CdiUtil.bean(Identity).setWorkingParameter("passwordScanFailedAnd2FAPassed","true")
                    #self.setError("Password validation failed. You have to authenticate yourself before proceeding")
                return result_2fa
            
            elif(CdiUtil.bean(Identity).getWorkingParameter("passwordNotSaved") == "true" and CdiUtil.bean(Identity).getWorkingParameter("passwordNotSavedAnd2FAPassed") != "true"):
                result_2fa = self.authenticate2FAStep(requestParameters, user, step)
                if result_2fa == True:
                    CdiUtil.bean(Identity).setWorkingParameter("passwordNotSavedAnd2FAPassed","true")
                    #self.setError("Password not saved. You have to authenticate yourself before proceeding")
                return result_2fa
            
            
            elif (CdiUtil.bean(Identity).getWorkingParameter("passwordNotSaved") == 'true' and CdiUtil.bean(Identity).getWorkingParameter("passwordNotSavedAnd2FAPassed") == 'true'):
                # TODO: we are never going to send the password here in plain text, this check should be removed
                #password2 = ServerUtil.getFirstValue(requestParameters, "login_form:password2")
                #if StringHelper.isEmpty(password):
                #    self.setError("Password cannot be empty.")
                #    print "Password cannot be empty."
                #    CdiUtil.bean(Identity).setWorkingParameter("passwordSaved","false")
                #    return True
                
                k_pwd = ServerUtil.getFirstValue(requestParameters, "k_pwd")
                print "k_pwd %s" % k_pwd
                
                result = self.validateKeystrokesPy(username, identity.getWorkingParameter("k_username"), k_pwd )
                print "result %s" % result
                if(result == True):
                    # Gluu Authentication complete
                    print "Passwurd. Authentication successful."
                    
                    # TODO: check that - only if MFA was invoked in a prev step, then this needs to be added
                    result = self.notifyProfilePy(username, True)
                    user.setAttribute("userPassword", "true")
                    userService.updateUser(user)
                    return True
                else:
                    #TODO: what to do here -  Gluu authentication not complete, go for 2FA
                    CdiUtil.bean(Identity).setWorkingParameter("passwordScanFailed","true")
                    return True
                
            
            else:
            # (Password has been saved in the past and user is authenticating using his password)
            # invoke the GLuu Scan API and validate the pwd
            # if it fails, save this session variable passwordScanFailed, and proceed to step 3 is 2FA by casa script
                #password = ServerUtil.getFirstValue(requestParameters, "pwd")
                k_pwd = ServerUtil.getFirstValue(requestParameters, "k_pwd")
                print "k_pwd %s" % k_pwd
                
                result = self.validateKeystrokesPy(username, identity.getWorkingParameter("k_username"), k_pwd)
                print "result %s" % result
                if(result == True):
                    # Gluu Authentication complete
                    print "Passwurd. Authentication successful."
                    # access_token = self.getAccessTokenJansServer()
                    # TODO: check that - only if MFA was invoked in a prev step, then this needs to be added
                    result = self.notifyProfilePy(username, True)
                    return True
                else:
                    # Gluu authentication not complete, go for 2FA
                    CdiUtil.bean(Identity).setWorkingParameter("passwordScanFailed","true")
                    return True
        return False
        

    def prepareForStep(self, configurationAttributes, requestParameters, step):
        print "Passwurd. prepareForStep %d" % step

        identity = CdiUtil.bean(Identity)
        session_attributes = identity.getSessionId().getSessionAttributes()
        
        if step == 1:
            try:
                loginHint = session_attributes.get("login_hint")
                print "Passwurd. prepareForStep. Login hint is %s" % loginHint
                isLoginHint = loginHint != None
                if self.prevLoginsSettings == None:
                    if isLoginHint:
                        identity.setWorkingParameter("loginHint", loginHint)
                else:
                    users = self.getCookieValue()    
                    if isLoginHint:
                        idx = self.findUid(loginHint, users) 
                        if idx >= 0:
                            u = users.pop(idx)
                            users.insert(0, u)
                        else:
                            identity.setWorkingParameter("loginHint", loginHint)
                    
                    if len(users) > 0:
                        identity.setWorkingParameter("users", json.dumps(users, separators=(',',':')))
            
                    # In login.xhtml both loginHint and users are used to properly display the login form
            except:
                print "Passwurd. prepareForStep. Error!", sys.exc_info()[1]
                
            return True
            
        elif step == 2:
            user = CdiUtil.bean(AuthenticationService).getAuthenticatedUser()
            if user == None:
                print "Passwurd. prepareForStep. Cannot retrieve logged user"
                return False
            
            # password does not exist, step 2 is 2FA authentication
            if user.getAttribute("userPassword") == None and CdiUtil.bean(Identity).getWorkingParameter("passwordNotSavedAnd2FAPassed") != "true":
                CdiUtil.bean(Identity).setWorkingParameter("passwordNotSaved","true")
                self.setError("Password not saved. You have to authenticate yourself before proceeding")
                twoFA_result = self.get2FAPrepareForStep ( user, identity.getWorkingParameter("ACR"), requestParameters, step)
                return twoFA_result
            
                
            if CdiUtil.bean(Identity).getWorkingParameter("passwordNotSaved") == "true":
            # case 1  : saving the password    
                print "Passwurd. user password does not  exists and user will be presented with the save password page which goes to the /enroll endpoint of Gluu scan API"   
                return True
            elif CdiUtil.bean(Identity).getWorkingParameter("passwordScanFailed") == "true" :
            # case 2: 2FA authentication
                self.setError("Password validation failed. You have to authenticate yourself before proceeding")
                twoFA_result = self.get2FAPrepareForStep ( user, identity.getWorkingParameter("ACR"), requestParameters, step)
                return twoFA_result
            else:
                # presenting the enterPwd page
                # do nothing 
                return True

        else:
            print "Passwurd. Something went wrong"
            return False   

    def getExtraParametersForStep(self, configurationAttributes, step):

        print "Passwurd. getExtraParametersForStep %d" % step
        list = ArrayList()
        if step > 1:
            acr = CdiUtil.bean(Identity).getWorkingParameter("ACR")

            if acr in self.authenticators:
                module = self.authenticators[acr]
                params = module.getExtraParametersForStep(module.configAttrs, step)
                if params != None:
                    list.addAll(params)
            list.addAll(Arrays.asList("ACR", "methods", "passwordNotSaved", "passwordNotSavedAnd2FAPassed", "passwordScanFailed","passwordScanFailedAnd2FAPassed", "passwordSaved", "k_username", "k_pwd"))
            print "extras are %s" % list
        return list

    def getCountAuthenticationSteps(self, configurationAttributes):
        return 2

    def getPageForStep(self, configurationAttributes, step):
        print "getPageForStep %s" % step
        if step > 1:
            page = None
            acr = CdiUtil.bean(Identity).getWorkingParameter("ACR")
            if acr in self.authenticators and (( CdiUtil.bean(Identity).getWorkingParameter("passwordNotSaved") == "true" and CdiUtil.bean(Identity).getWorkingParameter("passwordNotSavedAnd2FAPassed") != "true") or (CdiUtil.bean(Identity).getWorkingParameter("passwordScanFailed") == "true" and CdiUtil.bean(Identity).getWorkingParameter("passwordScanFailedAnd2FAPassed") != "true")):
                module = self.authenticators[acr]
                print module
                page = module.getPageForStep(module.configAttrs, 2)
                
                print "Passwurd. getPageForStep %d is %s" % (2, page)                
                return page
            
            if CdiUtil.bean(Identity).getWorkingParameter("passwordNotSaved") == "true" and CdiUtil.bean(Identity).getWorkingParameter("passwordNotSavedAnd2FAPassed") == "true":
                return "/passwurd/savePwd.xhtml"
            
            elif CdiUtil.bean(Identity).getWorkingParameter("passwordNotSaved") is "true" or CdiUtil.bean(Identity).getWorkingParameter("passwordScanFailed") == "true":
                return page
            
            else: 
                return "/passwurd/enterPwd.xhtml"
            
        return "/passwurd/login.xhtml"

    
        
    def getNextStep(self, configurationAttributes, requestParameters, step):
        print "Passwurd. getNextStep called %d" % step
        
        if(step > 1):
            print "Passwurd. Step > 1"
            acr = ServerUtil.getFirstValue(requestParameters, "alternativeMethod")
            if acr != None:
                CdiUtil.bean(Identity).setWorkingParameter("ACR", acr)
                return 2
            
        user = CdiUtil.bean(AuthenticationService).getAuthenticatedUser()
        
        if(CdiUtil.bean(Identity).getWorkingParameter("passwordSaved") == "false"):
            print "passwordSaved"
            return 2
             
        if user.getAttribute("userPassword") is not None and CdiUtil.bean(Identity).getWorkingParameter("passwordNotSavedAnd2FAPassed") == "true" :
            return -1
        
        if CdiUtil.bean(Identity).getWorkingParameter("passwordScanFailedAnd2FAPassed") == "true":
            return -1
        
        if CdiUtil.bean(Identity).getWorkingParameter("passwordNotSavedAnd2FAPassed") == "true" :
            return 2
        # reset step to the previous step count, when alternative 2fa method is tried
        if CdiUtil.bean(Identity).getWorkingParameter("passwordScanFailed") == "true" and CdiUtil.bean(Identity).getWorkingParameter("passwordNotSavedAnd2FAPassed") is None:
            return step
        return -1

    def logout(self, configurationAttributes, requestParameters):
        return True

    # Miscelaneous

    def getLocalPrimaryKey(self):
        entryManager = CdiUtil.bean(PersistenceEntryManager)
        config = GluuConfiguration()
        config = entryManager.find(config.getClass(), "ou=configuration,o=gluu")
        #Pick (one) attribute where user id is stored (e.g. uid/mail)
        uid_attr = config.getOxIDPAuthentication().get(0).getConfig().getPrimaryKey()
        print "Passwurd. init. uid attribute is '%s'" % uid_attr
        return uid_attr


    def setError(self, msg):
        facesMessages = CdiUtil.bean(FacesMessages)
        facesMessages.setKeepMessages()
        facesMessages.clear()
        facesMessages.add(FacesMessage.SEVERITY_ERROR, msg)


    def computeMethods(self, sndStepMethods, scriptsList):
        snd_step_methods = [] if sndStepMethods == None else StringHelper.split(sndStepMethods.getValue2(), ",")        
        methods = []
        
        for m in snd_step_methods:
            for customScript in scriptsList:
                if customScript.getName() == m and customScript.isEnabled():
                    methods.append(m)

        print "Passwurd. computeMethods. %s" % methods
        return methods


    def getConfigurationAttributes(self, acr, scriptsList):

        configMap = HashMap()
        for customScript in scriptsList:
            if customScript.getName() == acr:
                for prop in customScript.getConfigurationProperties():
                    configMap.put(prop.getValue1(), SimpleCustomProperty(prop.getValue1(), prop.getValue2()))

        print "Passwurd. getConfigurationAttributes. %d configuration properties were found for %s" % (configMap.size(), acr)
        return configMap


    def getAvailMethodsUser(self, user, skip=None):
        methods = ArrayList()
        for method in self.authenticators:
            try:
                module = self.authenticators[method]
                if module.hasEnrollments(module.configAttrs, user) and (skip == None or skip != method):
                    methods.add(method)
            except:
                print "Passwurd. getAvailMethodsUser. hasEnrollments call could not be issued for %s module" % method
                print "Exception: ", sys.exc_info()[1]

        print "Passwurd. getAvailMethodsUser %s" % methods.toString()
        return methods


    def simulateFirstStep(self, requestParameters, acr):
        #To simulate 1st step, there is no need to call:
        # getPageforstep (no need as user/pwd won't be shown again)
        # isValidAuthenticationMethod (by restriction, it returns True)
        # prepareForStep (by restriction, it returns True)
        # getExtraParametersForStep (by restriction, it returns None)
        print "Passwurd. simulateFirstStep. Calling authenticate (step 1) for %s module" % acr
        if acr in self.authenticators:
            module = self.authenticators[acr]
            auth = module.authenticate(module.configAttrs, requestParameters, 1)
            print "Passwurd. simulateFirstStep. returned value was %s" % auth
            
    def computePrevLoginsSettings(self, customProperty):
        settings = None
        if customProperty == None:
            print "Passwurd. Previous logins feature is not configured. Set config property '%s' if desired" % self.PREV_LOGIN_SETTING
        else:
            try:
                settings = json.loads(customProperty.getValue2())
                if settings['enabled']:
                	print "Passwurd. PrevLoginsSettings are %s" % settings
                else:
                    settings = None
                    print "Passwurd. Previous logins feature is disabled"
            except:
                print "Passwurd. Unparsable config property '%s'" % self.PREV_LOGIN_SETTING
            
        return settings
        
    def getCookieValue(self):
        ulist = []
        coo =  None
        httpRequest = ServerUtil.getRequestOrNull()
        
        if httpRequest != None:
            for cookie in httpRequest.getCookies():
                if cookie.getName() == self.prevLoginsSettings['cookieName']:
                   coo = cookie
        
        if coo == None:
            print "Passwurd. getCookie. No cookie found"
        else:
            print "Passwurd. getCookie. Found cookie"
            forgetMs = self.prevLoginsSettings['forgetEntriesAfterMinutes'] * 60 * 1000
            
            try:
                now = System.currentTimeMillis()
                value = URLDecoder.decode(coo.getValue(), "utf-8")
                # value is an array of objects with properties: uid, displayName, lastLogon
                value = json.loads(value)
                
                for v in value:
                    if now - v['lastLogon'] < forgetMs:
                        ulist.append(v)        
                # print "==========", ulist
            except:
                print "Passwurd. getCookie. Unparsable value, dropping cookie..."
            
        return ulist
        

    def findUid(self, uid, users):
        
        i = 0
        idx = -1
        for user in users:
            if user['uid'] == uid:
                idx = i
                break
            i+=1
        return idx
        
            
    def persistCookie(self, user):
        try:
            now = System.currentTimeMillis()
            uid = user.getUserId()
            dname = user.getAttribute("displayName")
            
            users = self.getCookieValue()
            idx = self.findUid(uid, users)
            
            if idx >= 0:
                u = users.pop(idx)
            else:
                u = { 'uid': uid, 'displayName': '' if dname == None else dname }
            u['lastLogon'] = now
            
            # The most recent goes first :)
            users.insert(0, u)
            
            excess = len(users) - self.prevLoginsSettings['maxListSize']            
            if excess > 0:
                print "Passwurd. persistCookie. Shortening list..."
                users = users[:self.prevLoginsSettings['maxListSize']]
            
            value = json.dumps(users, separators=(',',':'))
            value = URLEncoder.encode(value, "utf-8")
            coo = Cookie(self.prevLoginsSettings['cookieName'], value)
            coo.setSecure(True)
            coo.setHttpOnly(True)
            # One week
            coo.setMaxAge(7 * 24 * 60 * 60)
            
            response = self.getHttpResponse()
            if response != None:
                print "Passwurd. persistCookie. Adding cookie to response"
                response.addCookie(coo)
        except:
            print "Passwurd. persistCookie. Exception: ", sys.exc_info()[1]


    def getHttpResponse(self):
        try:
            return FacesContext.getCurrentInstance().getExternalContext().getResponse()
        except:
            print "Passwurd. Error accessing HTTP response object: ", sys.exc_info()[1]
            return None
        
    # invoking /authenticate endpoint of the GLUU PASSWURD API
    def authenticatePassword (self, password):
        print "Authenticating password: %s" % password
        return random.choice([True, False])
    
    # invoking /enroll endpoint of the GLUU PASSWURD API
    def enrollPassword (self, password):
        print "Enroll password: %s" % password
        return True #random.choice([True, False])
    
    def get2FAPrepareForStep (self, user, acr, requestParameters, step):
        methods = ArrayList(self.getAvailMethodsUser(user, acr))
        print "methods - %s" % methods
        CdiUtil.bean(Identity).setWorkingParameter("methods", methods)
        print "acr %s " % acr
        if acr in self.authenticators:
            module = self.authenticators[acr]
            return module.prepareForStep(module.configAttrs, requestParameters, step)
        else:
            return False

    def authenticate2FAStep(self, requestParameters, user, step):
        alter = ServerUtil.getFirstValue(requestParameters, "alternativeMethod")
        if alter != None:
            #bypass the rest of this step if an alternative method was provided. Current step will be retried (see getNextStep)
            self.simulateFirstStep(requestParameters, alter)
            return True

        session_attributes = CdiUtil.bean(Identity).getSessionId().getSessionAttributes()
        acr = session_attributes.get("ACR")
        #this working parameter is used in alternative.xhtml
        CdiUtil.bean(Identity).setWorkingParameter("methods", self.getAvailMethodsUser(user, acr))

        success = False
        if acr in self.authenticators:
            module = self.authenticators[acr]
            success = module.authenticate(module.configAttrs, requestParameters, step)

        if success:
            print "Passwurd. authenticate. 2FA authentication was successful"
            if self.prevLoginsSettings != None:
                self.persistCookie(user)
        else:
            print "Passwurd. authenticate. 2FA authentication failed"
            
        return success
    
    def signUid(self, uid):
        facesContext = CdiUtil.bean(FacesContext)
        alias = "snap.gluu.org" # facesContext.getExternalContext().getRequest().getServerName()
        print facesContext.getExternalContext().getRequest().getServerName()
        print uid
        signedUID = self.cryptoProvider.sign(uid,  alias, None, SignatureAlgorithm.RS256)
        print "SignedUID - %s" % signedUID
        return signedUID
    
    def getAccessTokenJansServer(self):
        
        url = self.AS_ENDPOINT +"/jans-auth/restv1/token"
        credentials = (self.AS_CLIENT_ID + ":" + self.AS_CLIENT_SECRET).encode("utf-8")
        encoded_credentials = base64.b64encode(credentials).decode("utf-8")
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": "Basic " + encoded_credentials,
        }
        body = "grant_type=client_credentials&scope=https://api.gluu.org/auth/scopes/scan.passwurd"
        status_code, response_string = self.executePost(url, body, headers)
        print "Passwurd token request. %s %s" % (status_code , response_string)
        if status_code == 200:
            response = json.loads(response_string)
            return response
        else:
            return None
    
    
    def validateKeystrokesPy(self, username, k_username, k_pwd):
        print "Passwurd. Validate call"
        try: 
            customer_sig = self.signUid(username)
            print customer_sig
            token_jwt = self.getAccessTokenJansServer()
            access_token = token_jwt["access_token"]
            org_id = token_jwt["org_id"]
            
            data_org = {"k_username": k_username, "k_pwd": k_pwd, "customer_sig": customer_sig, "org_id": org_id, "uid": username }
            
            for key in ('k_username', 'k_pwd'):
                data_org[key] = json.loads(data_org[key])
    
            
            data_org['user'] = username
            data_org['customer_sig'] = customer_sig
            
            body = json.dumps(data_org)
            headers = {
                "Content-Type": "application/json",
                "Authorization": "Bearer " + access_token
            }
            
            url = self.PASSWURD_API_URL +"/keystroke/validate"
            
            status_code, response_string = self.executePost(url, body, headers)
            print "Passwurd Validate. Status code: %s" % status_code
            print "Passwurd Validate. Response body: %s" % response_string
            if(status_code == 200):
                response_json = json.loads(response_string)
                if response_json["status"] == "Enrollment" or response_json["status"] == "Approved":
                    print "Keystrokes validated successfully"
                    return True
            else:
                print "Failed to validate keystrokes"
                return False
        except: 
            print "Failed to execute /keystroke/validate.", sys.exc_info()[1]
            return False
        return True
    
    def notifyProfilePy(self, username, mfaPassed):
        print "Passwurd. Notify call"
        token_jwt = self.getAccessTokenJansServer()
        access_token = token_jwt["access_token"]
        try:
            # TODO: track_id
            data_org = {  "uid": username, "track_id": None }
            body = json.dumps(data_org)
            headers = {
                "Content-Type": "application/json",
                "Authorization": "Bearer " + access_token
            }
            
            url = self.PASSWURD_API_URL +"/keystroke/notify"
            status_code, response_string = self.executePost(url, body, headers)
            print "Passwurd Notify. Status code: %s" % status_code
            print "Passwurd Notify. Response body: %s" % response_string
            if(status_code == 200):
                print "Keystrokes notify sent successfully"
            else:
                print "Failed to send keystrokes notify"
                return False
            
            response_data = json.loads(response_string)
            print response_data
            
        except:
            print "Failed to execute /keystroke/notify.", sys.exc_info()[1]
        # return true irrespective of the result
        return True
    
    def createClientPy(self, customScript):
        try: 

            register_uri = self.AS_ENDPOINT + "/jans-auth/restv1/register"
            body = {
                "redirect_uris" : [self.AS_REDIRECT_URI],
                "software_statement": self.AS_SSA,
                "jwks_uri": self.PORTAL_JWKS,
                "client_name": "Passwurd client from script"
            }
            request_headers = { "Content-type" : "application/json", "Accept" : "application/json" }
            body_string = json.dumps(body, indent=4)
            status_code, response_string = self.executePost(register_uri, body_string, request_headers)
            if status_code >= 300:
                print "Passwurd. Client registration failed: %s" % response_string
                return False
            response_data = json.loads(response_string)
            client_id = response_data["client_id"]
            client_secret = response_data["client_secret"]
            
            custScriptService = CdiUtil.bean(CustomScriptService)
            customScript = custScriptService.getScriptByDisplayName(customScript.getName())
            for conf in customScript.getConfigurationProperties():
                if (StringHelper.equalsIgnoreCase(conf.getValue1(), "AS_CLIENT_ID")):
                    conf.setValue2(client_id)
                elif (StringHelper.equalsIgnoreCase(conf.getValue1(), "AS_CLIENT_SECRET")):
                    conf.setValue2(client_secret)
            custScriptService.update(customScript)    
            print client_id
        except Exception as e: 
            print "Failed to execute /register: %s", e
            return False
        return True
    
    # Wrapper function for HttpService
    def executePost(self, request_uri, request_data, request_headers):
        httpService = CdiUtil.bean(HttpService)
        try:
            http_service_response = httpService.executePost(self.http_client, request_uri, None, request_headers, request_data)
            http_response = http_service_response.getHttpResponse()
        except:
            print "PASSWURD. Execute POST failed: ", sys.exc_info()[1]
            return None
        
        status_code = http_response.getStatusLine().getStatusCode()
        response_bytes = httpService.getResponseContent(http_response)
        if response_bytes is not None:
            response_string = httpService.convertEntityToString(response_bytes)
        else:
            response_string = None
        httpService.consume(http_response)
        http_service_response.closeConnection()
        return status_code, response_string
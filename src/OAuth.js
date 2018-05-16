var CustomError = require('twiz-client-utils').CustomError;
var percentEncode = require('twiz-client-utils').percentEncode;
var Options     = require('twiz-server-options');
var hmacSha1    = require('hmac_sha1')

 function OAuth(){
     CustomError.call(OAuth);
     OAuth.addCustomErrors({
        oauthTokenMissing: "oauth_token is missing",
        oauthTokenSecretMissing: "oauth_token_secret is missing"
     })
    

  }

  OAuth.prototype = Object.create(Options.prototype);
  
  OAuth.safeKeepAccessToken = function(tokenObj, vault){ // if we have access token data , keep it in vault
      if(tokenObj){
         this.checkAccessToken(tokenObj);
         vault.accessToken = tokenObj;
      }
      else vault.accessToken = '';
  }

  OAuth.checkAccessToken = function(tokenObj){           // check token object for access token data
 
      if(!tokenObj.oauth_token) {
         throw this.CustomError('oauthTokenMissing');     
      }
      
      if(!tokenObj.oauth_token_secret) {
         throw this.CustomError('oauthTokenSecretMissing');
      } 
   }
   
   OAuth.prototype.insertConsumerKey = function(vault, options, phase){// insert missing consumer key in 
                                                                       // SBS and AHS

      var consumer_key = options.missingVal_SBS.consumer_key;// get consumer key name (as it stands in OAuth Spec
      var value = vault.consumer_key;                        // Get value of consumer key from vault 
      
      options.SBS_AHS_insert(phase, consumer_key, value)   // insert consumer key to SBS and AHS
   };

   OAuth.prototype.insertAccessToken = function(vault, options, phase){
      var tokenName  = options.missingVal_SBS.token;       // take the key name
      var tokenValue = vault.accessToken.oauth_token;      // take the key value 

      console.log('missingVal_SBS.token: ', options.missingVal_SBS.token) 
      options.SBS_AHS_insert(phase, tokenName, tokenValue); // insert token in SBS and AHS  
   }
   
      
   OAuth.prototype.insertSignature = function(vault, options, phase){ // creates signature and 
      var accessToken = vault.accessToken;                               // inserts it
                                                                         // into Authorization Header string
      var HmacSha1 = new hmacSha1('base64');                             // Create new hmac function
      var signingKey = percentEncode(vault.consumer_secret) + "&";       // Prepare consumer_secret

      if(phase !== 'leg') signingKey = signingKey + percentEncode(accessToken.oauth_token_secret); 
                                                                                          // on non OAuth calls
                                                                                          // add token_secret

      var sbs = options[phase + 'SBS'];                           // get SBS
      var signature = HmacSha1.digest(signingKey, sbs);          // calculates oauth_signature

      
      var ahs = options[phase + 'AH'];                            // get ah
      var key = options.missingVal_AHS.signature;                // take key name 
      options[phase + 'AH'] = options.insertKey(ahs, options.missingVal_AHS, key, signature, true); 
                                                                         // inserts signature into AHS
      console.log(" SIGNATURE: " + signature);
      console.log(" AHS: " + options[phase + 'AH']); 
   };

   OAuth.prototype.finalizeOptions = function(options, phase){ // sets final options that we send in twitter req 
      options.host    = options[phase + 'Host']; // when you start sending pref+ Host in  queryString
      options.path    = options[phase + 'Path'];
      options.method  = options[phase + 'Method'];
 
      options.headers.authorization = options[phase + 'AH']; // sets authorization header 
  }

  module.exports = OAuth

using Amazon;
using Amazon.CognitoIdentityProvider;
using Amazon.CognitoIdentityProvider.Model;
using Amazon.Runtime;
using Microsoft.AspNetCore.Authentication;

namespace NET6AWSCognitoWebApp.Helpers
{
    public class UserHelper : IUserHelper
    {
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly IConfiguration _configuration;
        private readonly AmazonCognitoIdentityProviderClient _client;

        private readonly string ACCESS_TOKEN = "access_token";

        public UserHelper(IHttpContextAccessor httpContextAccessor, IConfiguration configuration)
        {
            _httpContextAccessor = httpContextAccessor;
            _configuration = configuration;

            //Setup client and apply region from appsettings
            _client = new AmazonCognitoIdentityProviderClient(new AnonymousAWSCredentials(), RegionEndpoint.GetBySystemName(_configuration.GetValue<string>("Authentication:Cognito:Region")));
        }//UserHelper

        public async Task<GetUserResponse> GetUserAsync()
        {
            var token = await _httpContextAccessor.HttpContext.GetTokenAsync(ACCESS_TOKEN);
            var response = await _client.GetUserAsync(new GetUserRequest()
            {
                AccessToken = token
            });
            return response;
        }//GetUserAsync

        public async Task<ChangePasswordResponse> ChangePasswordAsync(string aPreviousPassword, string aProposedPassword)
        {
            try
            {
                var token = await _httpContextAccessor.HttpContext.GetTokenAsync(ACCESS_TOKEN);
                // Amazon Cognito uses an exponentially increasing lockout timer for failed attempts. Test with care.
                // https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-authentication-flow.html
                var response = await _client.ChangePasswordAsync(new ChangePasswordRequest()
                {
                    AccessToken = token,
                    PreviousPassword = aPreviousPassword,
                    ProposedPassword = aProposedPassword
                });
                return response;
            }
            catch (Exception)
            {
                throw;
            }
        }//ChangePasswordAsync

        public async Task<UpdateUserAttributesResponse> UpdateUserAttributesAsync(List<AttributeType> aAttributeTypeList)
        {
            var token = await _httpContextAccessor.HttpContext.GetTokenAsync(ACCESS_TOKEN);
            try
            {
                var response = await _client.UpdateUserAttributesAsync(new UpdateUserAttributesRequest()
                {
                    AccessToken = token,
                    UserAttributes = aAttributeTypeList
                });
                return response;
            }
            catch (Exception)
            {
                throw;
            }
        }//UpdateUserAttributesAsync

        public async Task<UpdateUserAttributesResponse> AddPhoneNumberAsync(string aPhoneNumber)
        {
            var token = await _httpContextAccessor.HttpContext.GetTokenAsync(ACCESS_TOKEN);
            try
            {
                // build user attribute list with new phone number
                var myUserAttributes = new List<AttributeType>();
                myUserAttributes.Add(new AttributeType()
                {
                    Name = "phone_number",
                    Value = aPhoneNumber
                });
                // update user attributes
                var response = await _client.UpdateUserAttributesAsync(new UpdateUserAttributesRequest()
                {
                    AccessToken = token,
                    UserAttributes = myUserAttributes
                }); ;
                return response;
            }
            catch (Exception)
            {
                throw;
            }
        }//AddPhoneNumberAsync

        public async Task<GetUserAttributeVerificationCodeResponse> SendPhoneNumberVerificationAsync()
        {
            var token = await _httpContextAccessor.HttpContext.GetTokenAsync(ACCESS_TOKEN);
            try
            {
                var response = await _client.GetUserAttributeVerificationCodeAsync(new GetUserAttributeVerificationCodeRequest()
                {
                    AccessToken = token,
                    AttributeName = "phone_number"
                });
                return response;
            }
            catch (Exception)
            {
                throw;
            }
        }//SendPhoneNumberVerificationAsync

        public async Task<VerifyUserAttributeResponse> VerifyPhoneNumberAsync(string aVerificationCode)
        {
            var token = await _httpContextAccessor.HttpContext.GetTokenAsync(ACCESS_TOKEN);
            try
            {
                var response = await _client.VerifyUserAttributeAsync(new VerifyUserAttributeRequest()
                {
                    AccessToken = token,
                    AttributeName = "phone_number",
                    Code = aVerificationCode
                });
                return response;
            }
            catch (Exception)
            {
                throw;
            }
        }//VerifyPhoneNumberAsync

        public async Task<SetUserMFAPreferenceResponse> EnableSMSMFAAsync()
        {
            var token = await _httpContextAccessor.HttpContext.GetTokenAsync(ACCESS_TOKEN);
            try
            {
                var response = await _client.SetUserMFAPreferenceAsync(new SetUserMFAPreferenceRequest
                {
                    AccessToken = token,
                    SMSMfaSettings = new SMSMfaSettingsType()
                    {
                        Enabled = true,
                        PreferredMfa = true
                    }
                });
                return response;
            }
            catch (Exception)
            {
                throw;
            }
        }//EnableSMSMFAAsync

        public async Task<SetUserMFAPreferenceResponse> DisableSMSMFAAsync()
        {
            var token = await _httpContextAccessor.HttpContext.GetTokenAsync(ACCESS_TOKEN);
            try
            {
                var response = await _client.SetUserMFAPreferenceAsync(new SetUserMFAPreferenceRequest
                {
                    AccessToken = token,
                    SMSMfaSettings = new SMSMfaSettingsType()
                    {
                        Enabled = false,
                        PreferredMfa = false
                    }
                });
                return response;
            }
            catch (Exception)
            {
                throw;
            }
        }//DisableSMSMFAAsync

        public async Task<AssociateSoftwareTokenResponse> GenerateSoftwareMFASecretAsync()
        {
            var token = await _httpContextAccessor.HttpContext.GetTokenAsync(ACCESS_TOKEN);
            try
            {
                var response = await _client.AssociateSoftwareTokenAsync(new AssociateSoftwareTokenRequest()
                {
                    AccessToken = token
                });
                return response;
            }
            catch(Exception)
            {
                throw;
            }
        }//GenerateSoftwareMFASecretAsync

        public async Task<VerifySoftwareTokenResponse> VerifySoftwareMFAAsync(string aUserCode, string aDeviceName)
        {
            var token = await _httpContextAccessor.HttpContext.GetTokenAsync(ACCESS_TOKEN);
            try
            {
                var response = await _client.VerifySoftwareTokenAsync(new VerifySoftwareTokenRequest
                {
                    AccessToken = token,
                    UserCode = aUserCode,
                    FriendlyDeviceName = aDeviceName
                });
                return response;
            }
            catch(Exception)
            {
                throw;
            }
        }//VerifySoftwareMFAAsync

        public async Task<SetUserMFAPreferenceResponse> EnableSoftwareMFAAsync()
        {
            var token = await _httpContextAccessor.HttpContext.GetTokenAsync(ACCESS_TOKEN);
            try
            {
                var response = await _client.SetUserMFAPreferenceAsync(new SetUserMFAPreferenceRequest
                {
                    AccessToken = token,
                    SoftwareTokenMfaSettings = new SoftwareTokenMfaSettingsType()
                    {
                        Enabled = true,
                        PreferredMfa = true
                    }
                });
                return response;
            }
            catch (Exception)
            {
                throw;
            }
        }//EnableSoftwareMFAAsync

        public async Task<SetUserMFAPreferenceResponse> DisableSoftwareMFAAsync()
        {
            var token = await _httpContextAccessor.HttpContext.GetTokenAsync(ACCESS_TOKEN);
            try
            {
                var response = await _client.SetUserMFAPreferenceAsync(new SetUserMFAPreferenceRequest
                {
                    AccessToken = token,
                    SoftwareTokenMfaSettings = new SoftwareTokenMfaSettingsType()
                    {
                        Enabled = false,
                        PreferredMfa = false
                    }
                });
                return response;
            }
            catch (Exception)
            {
                throw;
            }
        }//DisableSoftwareMFAAsync
    }
}

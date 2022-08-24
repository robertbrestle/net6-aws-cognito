using Amazon.CognitoIdentityProvider.Model;

namespace NET6AWSCognitoWebApp.Helpers
{
    public interface IUserHelper
    {
        Task<GetUserResponse> GetUserAsync();
        Task<UpdateUserAttributesResponse> UpdateUserAttributesAsync(List<AttributeType> aAttributeTypeList);
        Task<ChangePasswordResponse> ChangePasswordAsync(string aPreviousPassword, string aProposedPassword);
        Task<UpdateUserAttributesResponse> AddPhoneNumberAsync(string aPhoneNumber);
        Task<GetUserAttributeVerificationCodeResponse> SendPhoneNumberVerificationAsync();
        Task<VerifyUserAttributeResponse> VerifyPhoneNumberAsync(string aVerificationCode);
        Task<SetUserMFAPreferenceResponse> EnableSMSMFAAsync();
        Task<SetUserMFAPreferenceResponse> DisableSMSMFAAsync();
        Task<AssociateSoftwareTokenResponse> GenerateSoftwareMFASecretAsync();
        Task<VerifySoftwareTokenResponse> VerifySoftwareMFAAsync(string aUserCode, string aDeviceName);
        Task<SetUserMFAPreferenceResponse> EnableSoftwareMFAAsync();
        Task<SetUserMFAPreferenceResponse> DisableSoftwareMFAAsync();
    }
}

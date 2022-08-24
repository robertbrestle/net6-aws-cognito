using Amazon.CognitoIdentityProvider.Model;
using System.ComponentModel.DataAnnotations;

namespace NET6AWSCognitoWebApp.Models
{
    public class ManageSMSMFAViewModel
    {
        public GetUserResponse CognitoUserData { get; set; }
        public string PhoneNumber { get; set; }
        public string VerificationCode { get; set; }
        // boolean strings
        public string VerificationSent { get; set; }
        public string SuccessfulUpdate { get; set; }
    }

    public class UpdatePhoneNumberRequestModel
    {
        [Required]
        public string PhoneNumber { get; set; }
    }
}

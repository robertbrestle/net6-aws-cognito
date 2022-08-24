using Amazon.CognitoIdentityProvider.Model;
using System.ComponentModel.DataAnnotations;

namespace NET6AWSCognitoWebApp.Models
{
    public class ManageSoftwareMFAViewModel
    {
        //public GetUserResponse CognitoUserData { get; set; }
        public string SecretToken { get; set; }
        [Required]
        public string DeviceName { get; set; }
        [Required]
        public string VerificationCode { get; set; }
        // boolean strings
        public string SuccessfulUpdate { get; set; }
    }
}

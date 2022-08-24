using System.ComponentModel.DataAnnotations;

namespace NET6AWSCognitoWebApp.Models
{
    public class ChangePasswordViewModel
    {
        [Required]
        public string PreviousPassword { get; set; }
        [Required]
        public string ProposedPassword { get; set; }
        [Required]
        public string ProposedPasswordVerification { get; set; }
        public string SuccessfulUpdate { get; set; }
    }
}

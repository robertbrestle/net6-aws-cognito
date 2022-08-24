using System.ComponentModel.DataAnnotations;

namespace NET6AWSCognitoWebApp.Models
{
    public class EditAttributesViewModel
    {
        [Required]
        public string FirstName { get; set; }
        [Required]
        public string LastName { get; set; }
        [Required]
        public string Email { get; set; }
        public string PhoneNumber { get; set; }
        public string ExternalName { get; set; }
        public string ExternalValue { get; set; }
        public string SuccessfulUpdate { get; set; }
    }
}

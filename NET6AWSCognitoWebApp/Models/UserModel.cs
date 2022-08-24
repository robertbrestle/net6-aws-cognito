using Amazon.CognitoIdentityProvider.Model;

namespace NET6AWSCognitoWebApp.Models
{
    public class UserModel
    {
        public GetUserResponse CognitoUserData { get; set; }
    }
}

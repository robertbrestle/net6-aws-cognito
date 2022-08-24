using Amazon.CognitoIdentityProvider.Model;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using NET6AWSCognitoWebApp.Helpers;
using NET6AWSCognitoWebApp.Models;
using QRCoder;

namespace NET6AWSCognitoWebApp.Controllers
{
    public class AccountController : Controller
    {
        private readonly IConfiguration _config;
        private readonly IUserHelper _userHelper;

        public AccountController(IConfiguration aIConfiguration, IUserHelper aIUserHelper)
        {
            _config = aIConfiguration;
            _userHelper = aIUserHelper;
        }

        #region Account
        [Authorize]
        public async Task<IActionResult> Index()
        {
            try
            {
                UserModel myUserSettingsModel = new UserModel()
                {
                    CognitoUserData = await _userHelper.GetUserAsync()
                };

                // get user information
                return View(myUserSettingsModel);
            }
            catch (NotAuthorizedException)
            {
                // TODO: refresh user token
                // https://github.com/aws/aws-sdk-net-extensions-cognito/issues/24#issuecomment-478418746
                // WORKAROUND: log out the user
                return RedirectToAction("Logout", "Account");
            }
        }//Index

        public IActionResult AccessDenied()
        {
            return View();
        }

        public async Task Logout()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            await HttpContext.SignOutAsync(OpenIdConnectDefaults.AuthenticationScheme);
        }//Logout
        #endregion

        #region Change Password
        [Authorize]
        public IActionResult ChangePassword()
        {
            return View();
        }//ChangePassword

        [HttpPost]
        [Authorize]
        public async Task<IActionResult> ChangePassword(ChangePasswordViewModel myChangePasswordViewModel)
        {
            if (ModelState.IsValid)
            {
                // new password mismatch
                if(myChangePasswordViewModel.ProposedPassword != myChangePasswordViewModel.ProposedPasswordVerification)
                {
                    ModelState.AddModelError("ProposedPasswordVerification", "The new passwords do not match.");
                }else if(myChangePasswordViewModel.PreviousPassword == myChangePasswordViewModel.ProposedPassword) {
                    ModelState.AddModelError("ProposedPassword", "The current and new passwords match.");
                }
                else
                {
                    try
                    {
                        var response = await _userHelper.ChangePasswordAsync(myChangePasswordViewModel.PreviousPassword, myChangePasswordViewModel.ProposedPassword);
                        if(response.HttpStatusCode == System.Net.HttpStatusCode.OK)
                        {
                            myChangePasswordViewModel.SuccessfulUpdate = Boolean.TrueString;
                        }
                    }
                    catch(Exception e)
                    {
                        ModelState.AddModelError("ProposedPassword", e.Message);
                    }
                }
            }
            return View(myChangePasswordViewModel);
        }//ChangePassword POST
        #endregion

        #region Edit User Attributes
        [Authorize]
        public async Task<IActionResult> EditAttributes()
        {
            try
            {
                var user = await _userHelper.GetUserAsync();
                if (user.UserAttributes != null)
                {
                    EditAttributesViewModel myEditAttributesViewModel = MapUserAttributesToEditAttributesViewModel(user);
                    return View(myEditAttributesViewModel);
                }
            }catch(Exception) { }
            return View();
        }//EditAttributes

        [HttpPost]
        [Authorize]
        public async Task<IActionResult> EditAttributes(EditAttributesViewModel myEditAttributesViewModel)
        {
            if (ModelState.IsValid)
            {
                var myAttributeTypeList = MapEditAttributesToAttributeTypeList(myEditAttributesViewModel);
                if(myAttributeTypeList != null && myAttributeTypeList.Count > 0)
                {
                    try
                    {
                        var myUpdateUserAttributesResponse = await _userHelper.UpdateUserAttributesAsync(myAttributeTypeList);
                        if (myUpdateUserAttributesResponse.HttpStatusCode == System.Net.HttpStatusCode.OK)
                        {
                            myEditAttributesViewModel.SuccessfulUpdate = Boolean.TrueString;
                        }
                    }catch(Exception e)
                    {
                        ModelState.AddModelError("ALL", e.Message);
                    }
                }
            }
            return View(myEditAttributesViewModel);
        }//EditAttributes POST
        #endregion

        #region ManageMFA
        [Authorize]
        public async Task<IActionResult> ManageMFA()
        {
            try
            {
                UserModel myUserSettingsModel = new UserModel()
                {
                    CognitoUserData = await _userHelper.GetUserAsync()
                };

                // get user information
                return View(myUserSettingsModel);
            }
            catch (NotAuthorizedException)
            {
                // TODO: refresh user token
                // https://github.com/aws/aws-sdk-net-extensions-cognito/issues/24#issuecomment-478418746
                // WORKAROUND: log out the user
                return RedirectToAction("Logout", "Account");
            }
        }//ManageMFA
        #endregion

        #region SMS MFA
        [Authorize]
        public async Task<IActionResult> ManageSMSMFA()
        {
            try
            {
                ManageSMSMFAViewModel myManageSMSMFAViewModel = new ManageSMSMFAViewModel()
                {
                    CognitoUserData = await _userHelper.GetUserAsync()
                };

                // get user information
                return View(myManageSMSMFAViewModel);
            }
            catch (NotAuthorizedException)
            {
                // TODO: refresh user token
                // https://github.com/aws/aws-sdk-net-extensions-cognito/issues/24#issuecomment-478418746
                // WORKAROUND: log out the user
                return RedirectToAction("Logout", "Account");
            }
        }//ManageSMSMFA

        [HttpPost]
        [Authorize]
        public async Task<IActionResult> AddPhoneNumber(ManageSMSMFAViewModel myManageSMSMFAViewModel)
        {
            if (ModelState.IsValid)
            {
                try
                {
                    var myVerifyUserAttributeResponse = await _userHelper.AddPhoneNumberAsync(myManageSMSMFAViewModel.PhoneNumber);
                    if (myVerifyUserAttributeResponse.HttpStatusCode == System.Net.HttpStatusCode.OK)
                    {
                        myManageSMSMFAViewModel.CognitoUserData = await _userHelper.GetUserAsync();
                    }
                }
                catch (Exception e)
                {
                    ModelState.AddModelError("PhoneNumber", e.Message);
                }
            }
            return View("ManageSMSMFA", myManageSMSMFAViewModel);
        }//AddPhoneNumber POST

        [Authorize]
        public async Task<IActionResult> SendPhoneNumberVerification()
        {
            try
            {
                // get user information
                ManageSMSMFAViewModel myManageSMSMFAViewModel = new ManageSMSMFAViewModel()
                {
                    CognitoUserData = await _userHelper.GetUserAsync()
                };
                
                // send phone number verification
                var response = await _userHelper.SendPhoneNumberVerificationAsync();
                if(response.HttpStatusCode == System.Net.HttpStatusCode.OK)
                {
                    myManageSMSMFAViewModel.VerificationSent = Boolean.TrueString;
                }

                return View("ManageSMSMFA", myManageSMSMFAViewModel);
            }
            catch (Exception)
            {
                return RedirectToAction("Index", "Account");
            }
        }//SendPhoneNumberVerification

        [HttpPost]
        [Authorize]
        public async Task<IActionResult> VerifyPhoneNumber(ManageSMSMFAViewModel myManageSMSMFAViewModel)
        {
            if (ModelState.IsValid)
            {
                try
                {
                    // set user data
                    myManageSMSMFAViewModel.CognitoUserData = await _userHelper.GetUserAsync();

                    // verify phone number
                    var verifyResponse = await _userHelper.VerifyPhoneNumberAsync(myManageSMSMFAViewModel.VerificationCode);
                    if (verifyResponse.HttpStatusCode == System.Net.HttpStatusCode.OK)
                    {
                        // enable SMS
                        var enableMFAResponse = await _userHelper.EnableSMSMFAAsync();
                        if(enableMFAResponse.HttpStatusCode == System.Net.HttpStatusCode.OK)
                        {
                            myManageSMSMFAViewModel.SuccessfulUpdate = Boolean.TrueString;
                        }
                    }
                }
                catch (Exception e)
                {
                    ModelState.AddModelError("VerificationCode", e.Message);
                }
            }
            return View("ManageSMSMFA", myManageSMSMFAViewModel);
        }//VerifyPhoneNumber POST

        [Authorize]
        public async Task<IActionResult> EnableSMSMFA()
        {
            // get user information
            ManageSMSMFAViewModel myManageSMSMFAViewModel = new ManageSMSMFAViewModel()
            {
                CognitoUserData = await _userHelper.GetUserAsync()
            };

            try
            {
                // send phone number verification
                var response = await _userHelper.EnableSMSMFAAsync();
                if (response.HttpStatusCode == System.Net.HttpStatusCode.OK)
                {
                    myManageSMSMFAViewModel.SuccessfulUpdate = Boolean.TrueString;
                }
            }
            catch (Exception e)
            {
                ModelState.AddModelError("All", e.Message);
            }

            return View("ManageSMSMFA", myManageSMSMFAViewModel);
        }//DisableSMSMFA

        [Authorize]
        public async Task<IActionResult> DisableSMSMFA()
        {
            // get user information
            ManageSMSMFAViewModel myManageSMSMFAViewModel = new ManageSMSMFAViewModel()
            {
                CognitoUserData = await _userHelper.GetUserAsync()
            };

            try
            {
                // send phone number verification
                var response = await _userHelper.DisableSMSMFAAsync();
                if (response.HttpStatusCode == System.Net.HttpStatusCode.OK)
                {
                    myManageSMSMFAViewModel.SuccessfulUpdate = Boolean.TrueString;
                }
            }
            catch (Exception e)
            {
                ModelState.AddModelError("All", e.Message);
            }

            return View("ManageSMSMFA", myManageSMSMFAViewModel);
        }//DisableSMSMFA
        #endregion

        #region Software MFA
        [Authorize]
        public async Task<IActionResult> ManageSoftwareMFA()
        {
            try
            {
                ManageSoftwareMFAViewModel myManageSoftwareMFAViewModel = new ManageSoftwareMFAViewModel();

                var softwareTokenResponse = await _userHelper.GenerateSoftwareMFASecretAsync();
                if(softwareTokenResponse.HttpStatusCode == System.Net.HttpStatusCode.OK && !string.IsNullOrEmpty(softwareTokenResponse.SecretCode))
                {
                    myManageSoftwareMFAViewModel.SecretToken = softwareTokenResponse.SecretCode;
                    ViewData["QRCode_Image"] = GenerateQRCode(softwareTokenResponse.SecretCode);
                }

                return View(myManageSoftwareMFAViewModel);
            }
            catch (NotAuthorizedException)
            {
                // TODO: refresh user token
                // https://github.com/aws/aws-sdk-net-extensions-cognito/issues/24#issuecomment-478418746
                // WORKAROUND: log out the user
                return RedirectToAction("Logout", "Account");
            }
        }//ManageSoftwareMFA

        private string GenerateQRCode(string aSecretToken)
        {
            // generate QRCode
            PayloadGenerator.OneTimePassword myPayloadGenerator = new PayloadGenerator.OneTimePassword()
            {
                Secret = aSecretToken,
                Issuer = _config.GetValue<string>("Authentication:TOTP:Issuer"),
                Label = User.Identity.Name
            };
            string myPayload = myPayloadGenerator.ToString();

            QRCodeGenerator myQRCodeGenerator = new QRCodeGenerator();
            QRCodeData myQRCodeData = myQRCodeGenerator.CreateQrCode(myPayload, QRCodeGenerator.ECCLevel.Q);

            // .NET 6 fix for System.Drawing issue
            // https://github.com/codebude/QRCoder/issues/361#issuecomment-992152570
            PngByteQRCode myPngByteQRCode = new PngByteQRCode(myQRCodeData);
            byte[] myQRCodeBytes = myPngByteQRCode.GetGraphic(20);

            return "data:image/png;base64," + Convert.ToBase64String(myQRCodeBytes.ToArray());
        }//GenerateQRCode

        [HttpPost]
        [Authorize]
        public async Task<IActionResult> ManageSoftwareMFA(ManageSoftwareMFAViewModel myManageSoftwareMFAViewModel)
        {
            if (ModelState.IsValid)
            {
                try
                {
                    var verificationResponse = await _userHelper.VerifySoftwareMFAAsync(myManageSoftwareMFAViewModel.VerificationCode, myManageSoftwareMFAViewModel.DeviceName);
                    if (verificationResponse.HttpStatusCode == System.Net.HttpStatusCode.OK)
                    {
                        var enableResponse = await _userHelper.EnableSoftwareMFAAsync();
                        if (verificationResponse.HttpStatusCode == System.Net.HttpStatusCode.OK)
                        {
                            myManageSoftwareMFAViewModel.SuccessfulUpdate = Boolean.TrueString;
                        }
                    }
                }
                catch (Exception e)
                {
                    ModelState.AddModelError("VerificationCode", e.Message);
                }
            }else
            {
                // generate new secret + QRCode
                var softwareTokenResponse = await _userHelper.GenerateSoftwareMFASecretAsync();
                if (softwareTokenResponse.HttpStatusCode == System.Net.HttpStatusCode.OK && !string.IsNullOrEmpty(softwareTokenResponse.SecretCode))
                {
                    myManageSoftwareMFAViewModel.SecretToken = softwareTokenResponse.SecretCode;
                    ViewData["QRCode_Image"] = GenerateQRCode(softwareTokenResponse.SecretCode);
                }

                // TODO: try to use existing secret, as this forces the user to delete scanned QRCode from their authenticator app
                ModelState.AddModelError("All", "If you have already scanned the QRCode into your authenticator app, please remove it and complete the form again.");
            }
            return View(myManageSoftwareMFAViewModel);
        }//ManageSoftwareMFA POST

        [Authorize]
        public async Task<IActionResult> DisableSoftwareMFA()
        {
            ManageSoftwareMFAViewModel myManageSoftwareMFAViewModel = new ManageSoftwareMFAViewModel();
            try
            {
                // send phone number verification
                var response = await _userHelper.DisableSoftwareMFAAsync();
                if (response.HttpStatusCode == System.Net.HttpStatusCode.OK)
                {
                    myManageSoftwareMFAViewModel.SuccessfulUpdate = Boolean.TrueString;
                }
            }
            catch (Exception e)
            {
                ModelState.AddModelError("All", e.Message);
            }

            return View("ManageSoftwareMFA", myManageSoftwareMFAViewModel);
        }//DisableSMSMFA
        #endregion

        #region Mappers
        private List<AttributeType> MapEditAttributesToAttributeTypeList(EditAttributesViewModel myEditAttributesViewModel)
        {
            List<AttributeType> myAttributeTypeList = new List<AttributeType>();

            #region Field Mappings
            if (!string.IsNullOrEmpty(myEditAttributesViewModel.FirstName))
            {
                myAttributeTypeList.Add(new AttributeType()
                {
                    Name = "given_name",
                    Value = myEditAttributesViewModel.FirstName
                });
            }
            if (!string.IsNullOrEmpty(myEditAttributesViewModel.LastName))
            {
                myAttributeTypeList.Add(new AttributeType()
                {
                    Name = "family_name",
                    Value = myEditAttributesViewModel.LastName
                });
            }
            if (!string.IsNullOrEmpty(myEditAttributesViewModel.Email))
            {
                myAttributeTypeList.Add(new AttributeType()
                {
                    Name = "email",
                    Value = myEditAttributesViewModel.Email
                });
            }
            if (!string.IsNullOrEmpty(myEditAttributesViewModel.PhoneNumber))
            {
                myAttributeTypeList.Add(new AttributeType()
                {
                    Name = "phone_number",
                    Value = myEditAttributesViewModel.PhoneNumber
                });
            }
            if (!string.IsNullOrEmpty(myEditAttributesViewModel.ExternalName))
            {
                myAttributeTypeList.Add(new AttributeType()
                {
                    Name = "custom:external_name",
                    Value = myEditAttributesViewModel.ExternalName
                });
            }
            if (!string.IsNullOrEmpty(myEditAttributesViewModel.ExternalValue))
            {
                myAttributeTypeList.Add(new AttributeType()
                {
                    Name = "custom:external_value",
                    Value = myEditAttributesViewModel.ExternalValue
                });
            }
            #endregion

            return myAttributeTypeList;
        }//MapEditAttributesToAttributeTypeList

        private EditAttributesViewModel MapUserAttributesToEditAttributesViewModel(GetUserResponse aGetUserResponse)
        {
            EditAttributesViewModel myEditAttributesViewModel = new EditAttributesViewModel();

            if (aGetUserResponse != null && aGetUserResponse.UserAttributes != null)
            {
                myEditAttributesViewModel.FirstName = aGetUserResponse.UserAttributes.Where(x => x.Name == "given_name").Select(x => x.Value).FirstOrDefault();
                myEditAttributesViewModel.LastName = aGetUserResponse.UserAttributes.Where(x => x.Name == "family_name").Select(x => x.Value).FirstOrDefault();
                myEditAttributesViewModel.Email = aGetUserResponse.UserAttributes.Where(x => x.Name == "email").Select(x => x.Value).FirstOrDefault();
                myEditAttributesViewModel.PhoneNumber = aGetUserResponse.UserAttributes.Where(x => x.Name == "phone_number").Select(x => x.Value).FirstOrDefault();
                myEditAttributesViewModel.ExternalName = aGetUserResponse.UserAttributes.Where(x => x.Name == "custom:external_name").Select(x => x.Value).FirstOrDefault();
                myEditAttributesViewModel.ExternalValue = aGetUserResponse.UserAttributes.Where(x => x.Name == "custom:external_value").Select(x => x.Value).FirstOrDefault();
            }

            return myEditAttributesViewModel;
        }//MapUserAttributesToEditAttributesViewModel
        #endregion
    }
}

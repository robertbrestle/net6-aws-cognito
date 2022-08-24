using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace NET6AWSCognitoWebApp.Controllers
{
    public class AdminController : Controller
    {
        public AdminController() { }

        [Authorize(Policy = "AdminOnly")]
        [HttpGet]
        public IActionResult Index()
        {
            return View();
        }
    }
}

using Microsoft.AspNetCore.Mvc;

namespace NET6AWSCognitoWebApp.Controllers
{
    public class HomeController : Controller
    {
        private readonly IConfiguration _config;
        private readonly ILogger<HomeController> _logger;

        public HomeController(IConfiguration aIConfiguration, ILogger<HomeController> logger)
        {
            _logger = logger;
            _config = aIConfiguration;
        }

        public IActionResult Index()
        {
            return View();
        }

        // leverage CDN error pages
        public IActionResult Error(int? statusCode = null)
        {
            if (statusCode != null)
            {
                return StatusCode((int)statusCode);
            }
            return StatusCode(StatusCodes.Status500InternalServerError);
        }
    }
}

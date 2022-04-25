using Identity_Training_App.Models.View_Models;
using Microsoft.AspNetCore.Mvc;

namespace Identity_Training_App.Controllers
{
    public class AccountController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }
        [HttpGet]
        public async Task<IActionResult> Register()
        {
            var registerVM = new RegisterVM();
            return View(registerVM);
        }
    }
}

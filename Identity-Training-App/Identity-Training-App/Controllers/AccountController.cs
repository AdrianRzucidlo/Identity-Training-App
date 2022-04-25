using Microsoft.AspNetCore.Mvc;

namespace Identity_Training_App.Controllers
{
    public class AccountController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }
    }
}

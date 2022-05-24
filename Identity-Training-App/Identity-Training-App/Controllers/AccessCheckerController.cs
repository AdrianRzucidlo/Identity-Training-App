using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Identity_Training_App.Controllers
{
    [Authorize]
    public class AccessCheckerController : Controller
    {
        [AllowAnonymous]
        public IActionResult AllAccess()
        {
            return View();
        }

        public IActionResult AuthorizedAccess()
        {
            return View();
        }
        [Authorize(Roles ="User")]
        public IActionResult UserAccess()
        {
            return View();
        }
        public IActionResult AdminAccess()
        {
            return View();
        }

        public IActionResult AdminCreateAccess()
        {
            return View();
        }

        public IActionResult AdminCreateEditDeleteAccess()
        {
            return View();
        }

        public IActionResult AdminCreateEditDeleteSuperUserAccess()
        {
            return View();
        }
    }
}

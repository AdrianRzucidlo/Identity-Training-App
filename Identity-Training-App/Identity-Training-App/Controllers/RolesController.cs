using Identity_Training_App.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace Identity_Training_App.Controllers
{

    public class RolesController : Controller
    {
        private readonly ApplicationDbContext _db;
        private readonly UserManager<IdentityUser> _usermanager;
        private readonly RoleManager<IdentityUser> _rolemanager;

        public RolesController(ApplicationDbContext db, UserManager<IdentityUser> userManager, RoleManager<IdentityUser> rolemanager)
        {
            _db = db;
            _usermanager = userManager;
            _rolemanager = rolemanager;
        }
        public IActionResult Index()
        {
            var roles = _db.Roles.ToList();
            return View(roles);
        }
    }
}

using Identity_Training_App.Data;
using Identity_Training_App.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace Identity_Training_App.Controllers
{
    public class UserController : Controller
    {
        private readonly ApplicationDbContext _db;
        private readonly UserManager<IdentityUser> _usermanager;

        public UserController(ApplicationDbContext db,UserManager<IdentityUser> userManager)
        {
            _db = db;
            _usermanager = userManager;
        }
        public IActionResult Index()
        {
            var userlist = _db.ApplicationUser.ToList();
            var userRole = _db.UserRoles.ToList();
            var roles = _db.Roles.ToList();
            foreach(var user in userlist)
            {
                var role = userRole.FirstOrDefault(u=> u.UserId == user.Id);
                if(role == null)
                {
                    user.Role = "None";
                }
                else
                {
                    user.Role = roles.FirstOrDefault(u=> u.Id == role.RoleId).Name;
                }
            }
            return View(userlist);
        }
    }
}

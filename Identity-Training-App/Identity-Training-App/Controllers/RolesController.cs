using Identity_Training_App.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace Identity_Training_App.Controllers
{

    public class RolesController : Controller
    {
        private readonly ApplicationDbContext _db;
        private readonly UserManager<IdentityUser> _usermanager;
        private readonly RoleManager<IdentityRole> _rolemanager;

        public RolesController(ApplicationDbContext db, UserManager<IdentityUser> userManager, RoleManager<IdentityRole> rolemanager)
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

        [HttpGet]
        public IActionResult Upsert(string id)
        {
            if(String.IsNullOrEmpty(id))
            {
                return View();
            }
            else
            {
                //update
                var obj = _db.Roles.FirstOrDefault(u=>u.Id == id);
                return View(obj);
            }
        }
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Upsert(IdentityRole roleObj)
        {
            if(await _rolemanager.RoleExistsAsync(roleObj.Name))
            {
                //error
            }
            if(string.IsNullOrEmpty(roleObj.Id))
            {
                await _rolemanager.CreateAsync(new IdentityRole { Name = roleObj.Name});
            }
            else
            {
                var objRoleFromDb = _db.Roles.FirstOrDefault(u=>u.Id == roleObj.Id);
                objRoleFromDb.Name = roleObj.Name;
                objRoleFromDb.NormalizedName = roleObj.Name.ToUpper();
                var result = await _rolemanager.UpdateAsync(objRoleFromDb);
            }
            return RedirectToAction(nameof(Index));
        }
    }
}

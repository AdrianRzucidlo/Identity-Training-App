using Microsoft.AspNetCore.Authorization;

namespace Identity_Training_App.Authorize
{
    public class OnlySuperAdminChecker : AuthorizationHandler<OnlySuperAdminChecker>
    {
    }
}

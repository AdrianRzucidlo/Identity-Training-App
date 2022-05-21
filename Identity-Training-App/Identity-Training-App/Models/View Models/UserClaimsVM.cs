namespace Identity_Training_App.Models.View_Models
{
    public class UserClaimsVM
    {
        public string UserId { get; set; }
        public List<UserClaim> userClaims { get; set; }

        public UserClaimsVM()
        {
            userClaims = new List<UserClaim>();
        }
    }

    public class UserClaim
    {
        public string ClaimType { get; set; }

        public bool IsSelected { get; set; }
    }
}

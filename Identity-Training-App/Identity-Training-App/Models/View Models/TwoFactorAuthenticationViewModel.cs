namespace Identity_Training_App.Models.View_Models
{
    public class TwoFactorAuthenticationViewModel
    {
        //to login
        public string Code { get; set; }
        //to register
        public string Token { get; set; }
    }
}

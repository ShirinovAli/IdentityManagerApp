namespace IdentityManagerApp.Models.ViewModels
{
    public class TwoFactorAuthenticationModel
    {
        public string Code { get; set; }
        public string? Token { get; set; }
    }
}

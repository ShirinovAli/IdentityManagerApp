namespace IdentityManagerApp.Models.ViewModels
{
    public class RolesViewModel
    {
        public RolesViewModel()
        {
            RolesList = new List<RoleSelection>();
        }
        public AppUser User { get; set; }
        public List<RoleSelection> RolesList { get; set; }
    }

    public class RoleSelection
    {
        public string RoleName { get; set; }
        public bool IsSelected { get; set; }
    }
}

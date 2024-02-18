using System.Security.Claims;

namespace IdentityManagerApp.Data
{
    public static class ClaimStore
    {
        public static List<Claim> claimsList = new()
        {
            new Claim("Create", "Create"),
            new Claim("Edit", "Edit"),
            new Claim("Delete", "Delete")
        };
    }
}

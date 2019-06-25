using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.Graph;
using Microsoft.Identity.Web.Client;
using System.Threading.Tasks;
using WebApp_OpenIDConnect_DotNet.Infrastructure;
using WebApp_OpenIDConnect_DotNet.Services;

namespace WebApp_OpenIDConnect_DotNet.Controllers
{
    public class AccountController : Controller
    {
        private readonly ITokenAcquisition tokenAcquisition;
        private readonly WebOptions webOptions;

        public AccountController(ITokenAcquisition tokenAcquisition,
                      IOptions<WebOptions> webOptionValue)
        {
            this.tokenAcquisition = tokenAcquisition;
            this.webOptions = webOptionValue.Value;
        }

        /// <summary>
        /// AspNet core's default AuthorizeAttribute redirects to '/Account/AccessDenied' when it processes the Http code 403 (Unauthorized)
        /// Instead of implementing an Attribute class of our own to construct a redirect Url, we'd just implement our own to show an error message of
        /// our choice to the user.
        /// </summary>
        /// <returns></returns>
        [AllowAnonymous]
        public IActionResult AccessDenied()
        {
            return View();
        }

        [MsalUiRequiredExceptionFilter(Scopes = new[] { GraphScopes.DirectoryReadAll })]
        [Authorize(Policy = "MixedRole")]
        //[Authorize(Policy = "DirectoryViewerRole")]
        //[Authorize(Policy = "SubGroup2-Part1Only")]
        //[Authorize(Roles = AppRoles.DirectoryViewers)]
        public async Task<IActionResult> Groups()
        {
            string[] scopes = new[] { GraphScopes.DirectoryReadAll };

            GraphServiceClient graphServiceClient = GraphServiceClientFactory.GetAuthenticatedGraphClient(async () =>
            {
                string result = await tokenAcquisition.GetAccessTokenOnBehalfOfUser(
                       HttpContext, scopes);
                return result;
            }, webOptions.GraphApiUrl);

            var groups = await graphServiceClient.Me.MemberOf.Request().GetAsync();

            ViewData["Groups"] = groups.CurrentPage;

            return View();
        }

        //public static IEnumerable<string> GetGroupMembershipsByObjectId(string id = null)
        //{
        //    if (string.IsNullOrEmpty(id))
        //        id = ClaimsPrincipal.Current.FindFirst("http://schemas.microsoft.com/identity/claims/objectidentifier").Value;

        //    IList<string> groupMembership = new List<string>();
        //    try
        //    {
        //        ActiveDirectoryClient activeDirectoryClient;
        //        //ActiveDirectoryClient activeDirectoryClient = ActiveDirectoryClient;
        //        IUser user = activeDirectoryClient.Users.Where(u => u.ObjectId == id).ExecuteSingleAsync().Result;
        //        var userFetcher = (IUserFetcher)user;

        //        IPagedCollection<IDirectoryObject> pagedCollection = userFetcher.MemberOf.ExecuteAsync().Result;
        //        do
        //        {
        //            List<IDirectoryObject> directoryObjects = pagedCollection.CurrentPage.ToList();
        //            foreach (IDirectoryObject directoryObject in directoryObjects)
        //            {
        //                if (directoryObject is Group)
        //                {
        //                    var group = directoryObject as Group;
        //                    groupMembership.Add(group.DisplayName);
        //                }
        //            }
        //            pagedCollection = pagedCollection.GetNextPageAsync().Result;
        //        } while (pagedCollection != null);

        //    }
        //    catch (Exception e)
        //    {
        //        ExceptionHandler.HandleException(e);
        //        throw e;
        //    }

        //    return groupMembership;
        //}
    }
}
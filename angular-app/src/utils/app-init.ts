import { KeycloakService } from "keycloak-angular";
import { environment } from "../environments/environment";

export function initializer(keycloak: KeycloakService): () => Promise<any> {
  return (): Promise<any> => {
    return new Promise(async (resolve, reject) => {
      try {
        await keycloak.init({
          config: {
            url: environment.keycloak.issuer,
            realm: environment.keycloak.realm,
            clientId: environment.keycloak.clientId,
          },
          // If set a false you cannot get any information about the user (e.g. username)
          loadUserProfileAtStartUp: true,
          initOptions: {
            //   This is an action we specified on keycloak load
            //   We have two options : 'login-required'|'check-sso'
            //   If is set to 'login-required' this means your browser will do a full redirect to the Keycloak server and back to your application.
            //   If is set to  'check-sso'  instead this action will be performed in a hidden iframe, so your application resources only need to be loaded and parsed once by the browser.
            //   Then you will need to add the silentCheckSsoRedirectUri and create a html file   silent-check-sso.html with this content
            // <html>
            //    <body>
            //         <script>
            //           parent.postMessage(location.href, location.origin);
            //         </script>
            //      </body>
            // </html>
            onLoad: 'login-required',
            checkLoginIframe: true,
            // silentCheckSsoRedirectUri: window.location.origin + '/assets/silent-check-sso.html',
          },
          // By default, the keycloak-angular library add 'Authorization: Bearer TOKEN' header to all http requests
          // Add here if u want to exclude urls (to not have that header)
          bearerExcludedUrls: ['/assets']
        });

        resolve(resolve);
      } catch (err) {
        reject(err);
      }
    });
  };

}

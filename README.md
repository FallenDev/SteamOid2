# SteamOid2
```
<PackageReference Include="SteamOid2" Version="*" />
```

Library for integrating with Steam's Open-ID provider in .NET, as described here: https://partner.steamgames.com/doc/features/auth#website.

Available for .NET 9.0

## Usage
```cs
using SteamOid2;
using SteamOid2.API;

// A DI constructor is also available using IConfiguration in the .NET and .NET Standard targets.
ISteamOid2Client client = new SteamOid2Client("http://localhost:8001/", "http://localhost:8001/openid/login");
```

* Redirect **user** to `client.GetLoginUri()`;

* The user will log in, then a request will be sent to the backend at the callback URI.

* Use `client.ParseIdReponse(uri)` to see if the returned Status is successful.

* Send a **POST** request to `client.GetAuthorizeUri(uri)` to ask Steam to confirm that the Steam ID provided was actually logged in to (from the backend).

* Use `client.CheckAuthorizationResponse(response)` to check that the response from the **POST** indicates a valid login session.

If you're seeing `Error` when you try to log in from Steam, make sure the realm domain name is the same as the callback domain name.

## Generating a Strong Name Key/Pair

SteamOid2.dll has a strong name, which means you may want to generate your own to recompile it.

Create a .snk file. This file or its contents should not be shared.

```
Developer Powershell > cd "Location outside of repository"
Developer Powershell > sn -k SteamOid2.dll.snk
Developer Powershell > sn -p SteamOid2.dll.snk SteamOid2.dll.publickey
```

Copy the public key to your fork and replace the existing one if you want.

Set the `StrongNameKeyPath` property in the .csproj file to the path of the .snk file.

## Sample implementation with a console application and HttpListener
https://github.com/UncreatedStaff/SteamOid2/blob/master/SteamOid2.Sample/LoginHost.cs

### Steam Logo
©2024 Valve Corporation. Steam and the Steam logo are trademarks and/or registered trademarks of Valve Corporation in the U.S. and/or other countries.

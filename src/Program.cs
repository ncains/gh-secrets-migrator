using System.CommandLine;
using System.CommandLine.Invocation;
using System.CommandLine.Parsing;
using System;
using System.Text;
using Newtonsoft.Json.Linq;


namespace SecretsMigrator
{

public class Environment
{
    public string Name { get; set; }
    public int Id { get; set; }
}

    public static class Program
    {
        private static readonly OctoLogger _log = new();

        public static async Task Main(string[] args)
        {
            var root = new RootCommand
            {
                Description = "Migrates all secrets from one GitHub repo to another."
            };

            var sourceOrg = new Option<string>("--source-org")
            {
                IsRequired = true
            };
            var sourceRepo = new Option<string>("--source-repo")
            {
                IsRequired = true
            };
            var targetOrg = new Option<string>("--target-org")
            {
                IsRequired = true
            };
            var targetRepo = new Option<string>("--target-repo")
            {
                IsRequired = true
            };
            var sourcePat = new Option<string>("--source-pat")
            {
                IsRequired = true
            };
            var targetPat = new Option<string>("--target-pat")
            {
                IsRequired = true
            };
            var envsecs = new Option("--env-secrets")
            {
                IsRequired = false
            };
            var orgSecrets = new Option("--org-secrets")
            {
                IsRequired = false
            };
            var verbose = new Option("--verbose")
            {
                IsRequired = false
            };
            root.AddOption(sourceOrg);
            root.AddOption(sourceRepo);
            root.AddOption(targetOrg);
            root.AddOption(targetRepo);
            root.AddOption(sourcePat);
            root.AddOption(targetPat);
            root.AddOption(envsecs);
            root.AddOption(orgSecrets);
            root.AddOption(verbose);

            root.Handler = CommandHandler.Create<string, string, string, string, string, string, bool, bool, bool>(Invoke);

            await root.InvokeAsync(args);
        }

           public static string ConvertToCommaSeparated(List<string> stringList)
    {
        if (stringList == null || stringList.Count == 0)
        {
            return string.Empty;
        }

        StringBuilder result = new StringBuilder();
        for (int i = 0; i < stringList.Count - 1; i++)
        {
            result.Append(stringList[i]);
            result.Append(",");
        }

        result.Append(stringList[stringList.Count - 1]);
        return result.ToString();
    }

        public static async Task Invoke(string sourceOrg, string sourceRepo, string targetOrg, string targetRepo, string sourcePat, string targetPat, bool envsecs = false, bool orgSecrets = false, bool verbose = false)
        {
            _log.Verbose = verbose;

            _log.LogInformation("Migrating Secrets...");
            _log.LogInformation($"SOURCE ORG: {sourceOrg}");
            _log.LogInformation($"SOURCE REPO: {sourceRepo}");
            _log.LogInformation($"TARGET ORG: {targetOrg}");
            _log.LogInformation($"TARGET REPO: {targetRepo}");
            _log.LogInformation($"Org Secrets: {orgSecrets}");


            var branchName = "migrate-secrets";



            var githubClient = new GithubClient(_log, sourcePat);
            var githubApi = new GithubApi(githubClient, "https://api.github.com");

            List<Environment> environmentNames = new List<Environment>();




                var environmentsTaskArray = githubApi.GetRepoEnvironments(sourceOrg, sourceRepo);
                JArray environmentsArray = await environmentsTaskArray;

               foreach (JToken environment in environmentsArray)
                {
                  string name = (string)environment["name"];
                  int id = (int)environment["id"];

                  environmentNames.Add(new Environment{Name = name, Id = id});
                }
        

            var workflow = GenerateWorkflow(sourceOrg, sourceRepo, targetOrg, targetRepo, branchName, environmentNames, orgSecrets);


            var (publicKey, publicKeyId) = await githubApi.GetRepoPublicKey(sourceOrg, sourceRepo);
            await githubApi.CreateRepoSecret(sourceOrg, sourceRepo, publicKey, publicKeyId, "SECRETS_MIGRATOR_PAT", targetPat);
            await githubApi.CreateRepoSecret(sourceOrg, sourceRepo, publicKey, publicKeyId, "SECRETS_MIGRATOR_SOURCEPAT", sourcePat);

            var defaultBranch = await githubApi.GetDefaultBranch(sourceOrg, sourceRepo);
            var masterCommitSha = await githubApi.GetCommitSha(sourceOrg, sourceRepo, defaultBranch);
            await githubApi.CreateBranch(sourceOrg, sourceRepo, branchName, masterCommitSha);

            await githubApi.CreateFile(sourceOrg, sourceRepo, branchName, ".github/workflows/migrate-secrets.yml", workflow);
          
            _log.LogSuccess($"Secrets migration in progress. Check on status at https://github.com/{sourceOrg}/{sourceRepo}/actions");
        }

        private static string GenerateWorkflow(string sourceOrg, string sourceRepo, string targetOrg, string targetRepo, string branchName, List<Environment>  environments, bool orgs = false)
        {

            List<string> jobs = new List<string>();
            jobs.Add("repo");

            var output = $@"
name: move-secrets
on:
  push:
    branches: [ ""{branchName}"" ]
jobs:
";

            output = orgs ? output + $@"
  org:
    runs-on: windows-latest
    steps:
      - name: Install Crypto Package
        run: |
          Install-Package -Name Sodium.Core -ProviderName NuGet -Scope CurrentUser -RequiredVersion 1.3.0 -Destination . -Force
        shell: pwsh
      - name: Migrate Secrets
        run: |
          Write-Output ""Processing Org Secrets....""

          $sodiumPath = Resolve-Path "".\Sodium.Core.1.3.0\lib\\netstandard2.1\Sodium.Core.dll""
          [System.Reflection.Assembly]::LoadFrom($sodiumPath)


          $targetPat = $env:TARGET_PAT
          $sourcePat = $env:SOURCE_PAT


          $sourceHeaders = @{{
            ""Accept"" = ""application/vnd.github+json""
            ""Authorization"" = ""Bearer $sourcePat""
            ""X-GitHub-Api-Version"" = ""2022-11-28""
          }}

          $targetHeaders = @{{
            ""Accept"" = ""application/vnd.github+json""
            ""Authorization"" = ""Bearer $targetPat""
            ""X-GitHub-Api-Version"" = ""2022-11-28""
            ""Content-Type"" = ""application/json""
          }}

          $publicKeyResponse = Invoke-RestMethod -Uri ""https://api.github.com/orgs/$env:TARGET_ORG/actions/secrets/public-key"" -Method ""GET"" -Headers $targetHeaders
          $publicKey = [Convert]::FromBase64String($publicKeyResponse.key)
          $publicKeyId = $publicKeyResponse.key_id
          
          $repoSecret = Invoke-RestMethod -Uri ""https://api.github.com/orgs/$env:SOURCE_ORG/actions/secrets"" -Method ""GET"" -Headers $sourceHeaders
          Write-Output $repoSecret

          $repoSecretNames = @()
          foreach ($secret in $repoSecret.secrets) {{
            if ($secret.name -ne ""github_token"" -and $secret.name -ne ""SECRETS_MIGRATOR_PAT"" -and $secret.name -ne ""SECRETS_MIGRATOR_SOURCEPAT"") {{
              $repoSecretNames += $secret.name
            }}
          }}

          Write-Output $repoSecretNames

          $secretsObject =  ConvertFrom-Json -InputObject $env:ALL_SECRETS

          foreach ($repoSecret in $repoSecretNames) {{
              Write-Output ""Migrating Secret: $repoSecret""
              $secret = $secretsObject | Select-Object -ExpandProperty $repoSecret
              Write-Output $secret
              $secretBytes = [Text.Encoding]::UTF8.GetBytes($secret)
              $sealedPublicKeyBox = [Sodium.SealedPublicKeyBox]::Create($secretBytes, $publicKey)
              $encryptedSecret = [Convert]::ToBase64String($sealedPublicKeyBox)

              $bodyObject = @{{
                encrypted_value = ""$encryptedSecret"";
                key_id = ""$publicKeyId"";
                visibility=""private""
              }}

              $bodyJson = $bodyObject | ConvertTo-Json
              Write-Output $bodyJson

              $createSecretResponse = Invoke-RestMethod -Uri ""https://api.github.com/orgs/$env:TARGET_ORG/actions/secrets/$repoSecret"" -Headers $targetHeaders -Method ""PUT"" -Body $bodyJson
          }}

        env:
          ALL_SECRETS: ${{{{ toJSON(secrets) }}}}
          TARGET_PAT: ${{{{ secrets.SECRETS_MIGRATOR_PAT }}}}
          TARGET_ORG: '{targetOrg}'
          SOURCE_PAT: ${{{{ secrets.SECRETS_MIGRATOR_SOURCEPAT }}}}
          SOURCE_ORG: '{sourceOrg}'
        shell: pwsh
":output;

if (orgs) {
  jobs.Add("org");
}
            output = output + $@"
  repo:
    runs-on: windows-latest
    steps:
      - name: Install Crypto Package
        run: |
          Install-Package -Name Sodium.Core -ProviderName NuGet -Scope CurrentUser -RequiredVersion 1.3.0 -Destination . -Force
        shell: pwsh
      - name: Migrate Secrets
        run: |
          $sodiumPath = Resolve-Path "".\Sodium.Core.1.3.0\lib\\netstandard2.1\Sodium.Core.dll""
          [System.Reflection.Assembly]::LoadFrom($sodiumPath)


          $targetPat = $env:TARGET_PAT
          $sourcePat = $env:SOURCE_PAT


          $sourceHeaders = @{{
            ""Accept"" = ""application/vnd.github+json""
            ""Authorization"" = ""Bearer $sourcePat""
            ""X-GitHub-Api-Version"" = ""2022-11-28""
          }}

          $targetHeaders = @{{
            ""Accept"" = ""application/vnd.github+json""
            ""Authorization"" = ""Bearer $targetPat""
            ""X-GitHub-Api-Version"" = ""2022-11-28""
            ""Content-Type"" = ""application/json""
          }}

          $publicKeyResponse = Invoke-RestMethod -Uri ""https://api.github.com/repos/$env:TARGET_ORG/$env:TARGET_REPO/actions/secrets/public-key"" -Method ""GET"" -Headers $targetHeaders
          $publicKey = [Convert]::FromBase64String($publicKeyResponse.key)
          $publicKeyId = $publicKeyResponse.key_id
          
          $repoSecret = Invoke-RestMethod -Uri ""https://api.github.com/repos/$env:SOURCE_ORG/$env:SOURCE_REPO/actions/secrets"" -Method ""GET"" -Headers $sourceHeaders
          Write-Output $repoSecret

          $repoSecretNames = @()
          foreach ($secret in $repoSecret.secrets) {{
            if ($secret.name -ne ""github_token"" -and $secret.name -ne ""SECRETS_MIGRATOR_PAT"" -and $secret.name -ne ""SECRETS_MIGRATOR_SOURCEPAT"") {{
              $repoSecretNames += $secret.name
            }}
          }}

          Write-Output $repoSecretNames

          $secretsObject =  ConvertFrom-Json -InputObject $env:ALL_SECRETS

          foreach ($repoSecret in $repoSecretNames) {{
              Write-Output ""Migrating Secret: $repoSecret""
              $secret = $secretsObject | Select-Object -ExpandProperty $repoSecret
              Write-Output $secret
              $secretBytes = [Text.Encoding]::UTF8.GetBytes($secret)
              $sealedPublicKeyBox = [Sodium.SealedPublicKeyBox]::Create($secretBytes, $publicKey)
              $encryptedSecret = [Convert]::ToBase64String($sealedPublicKeyBox)

              $bodyObject = @{{
                encrypted_value = ""$encryptedSecret"";
                key_id = ""$publicKeyId"";
              }}

              $bodyJson = $bodyObject | ConvertTo-Json
              Write-Output $bodyJson

              $createSecretResponse = Invoke-RestMethod -Uri ""https://api.github.com/repos/$env:TARGET_ORG/$env:TARGET_REPO/actions/secrets/$repoSecret"" -Headers $targetHeaders -Method ""PUT"" -Body $bodyJson
          }}
        env:
          ALL_SECRETS: ${{{{ toJSON(secrets) }}}}
          TARGET_PAT: ${{{{ secrets.SECRETS_MIGRATOR_PAT }}}}
          TARGET_ORG: '{targetOrg}'
          TARGET_REPO: '{targetRepo}'
          SOURCE_PAT: ${{{{ secrets.SECRETS_MIGRATOR_SOURCEPAT }}}}
          SOURCE_ORG: '{sourceOrg}'
          SOURCE_REPO: '{sourceRepo}'
        shell: pwsh
";

foreach (Environment environment in environments) {

            output = output + $@"
  {environment.Name}:
    runs-on: windows-latest
    environment: {environment.Name}
    steps:
      - name: Install Crypto Package
        run: |
          Install-Package -Name Sodium.Core -ProviderName NuGet -Scope CurrentUser -RequiredVersion 1.3.0 -Destination . -Force
        shell: pwsh
      - name: Migrate Secrets
        run: |
          $sodiumPath = Resolve-Path "".\Sodium.Core.1.3.0\lib\\netstandard2.1\Sodium.Core.dll""
          [System.Reflection.Assembly]::LoadFrom($sodiumPath)


          $targetPat = $env:TARGET_PAT
          $sourcePat = $env:SOURCE_PAT


          $sourceHeaders = @{{
            ""Accept"" = ""application/vnd.github+json""
            ""Authorization"" = ""Bearer $sourcePat""
            ""X-GitHub-Api-Version"" = ""2022-11-28""
          }}

          $targetHeaders = @{{
            ""Accept"" = ""application/vnd.github+json""
            ""Authorization"" = ""Bearer $targetPat""
            ""X-GitHub-Api-Version"" = ""2022-11-28""
            ""Content-Type"" = ""application/json""
          }}

          $envBodyObject = @{{
                wait_timer = 0;
              }}

          $envBodyJson = $envBodyObject | ConvertTo-Json

          $targetEnvResponse = Invoke-RestMethod -Uri ""https://api.github.com/repos/$env:TARGET_ORG/$env:TARGET_REPO/environments/$env:ENVIRONMENT_NAME""  -Headers $targetHeaders -Method ""PUT"" -Body $envBodyJson
          $targetEnvResponseId = $targetEnvResponse.id
          Write-Output ""Target Environment ID: $targetEnvResponseId""

          $targetRepoResponse = Invoke-RestMethod -Uri ""https://api.github.com/repos/$env:TARGET_ORG/$env:TARGET_REPO""  -Headers $targetHeaders -Method ""GET"" 
          $targetRepoResponseId = $targetRepoResponse.id
          Write-Output ""Target Repo ID: $targetRepoResponseId""

          $sourceRepoResponse = Invoke-RestMethod -Uri ""https://api.github.com/repos/$env:SOURCE_ORG/$env:SOURCE_REPO""  -Headers $sourceHeaders -Method ""GET"" 
          $sourceRepoResponseId = $sourceRepoResponse.id
          Write-Output ""Source Repo ID: $sourceRepoResponseId""

          $publicKeyResponse = Invoke-RestMethod -Uri ""https://api.github.com/repositories/$targetRepoResponseId/environments/$env:ENVIRONMENT_NAME/secrets/public-key"" -Method ""GET"" -Headers $targetHeaders
          $publicKey = [Convert]::FromBase64String($publicKeyResponse.key)
          $publicKeyId = $publicKeyResponse.key_id
          
          $repoSecret = Invoke-RestMethod -Uri ""https://api.github.com/repositories/$sourceRepoResponseId/environments/$env:ENVIRONMENT_NAME/secrets"" -Method ""GET"" -Headers $sourceHeaders
          Write-Output $repoSecret

          $repoSecretNames = @()
          foreach ($secret in $repoSecret.secrets) {{
            if ($secret.name -ne ""github_token"" -and $secret.name -ne ""SECRETS_MIGRATOR_PAT"" -and $secret.name -ne ""SECRETS_MIGRATOR_SOURCEPAT"") {{
              $repoSecretNames += $secret.name
            }}
          }}

          Write-Output $repoSecretNames

          $secretsObject =  ConvertFrom-Json -InputObject $env:ALL_SECRETS

          foreach ($repoSecret in $repoSecretNames) {{
              Write-Output ""Migrating Secret: $repoSecret""
              $secret = $secretsObject | Select-Object -ExpandProperty $repoSecret
              Write-Output $secret
              $secretBytes = [Text.Encoding]::UTF8.GetBytes($secret)
              $sealedPublicKeyBox = [Sodium.SealedPublicKeyBox]::Create($secretBytes, $publicKey)
              $encryptedSecret = [Convert]::ToBase64String($sealedPublicKeyBox)

              $bodyObject = @{{
                encrypted_value = ""$encryptedSecret"";
                key_id = ""$publicKeyId"";
              }}

              $bodyJson = $bodyObject | ConvertTo-Json
              Write-Output $bodyJson
              $createSecretResponse = Invoke-RestMethod -Uri ""https://api.github.com/repositories/$targetRepoResponseId/environments/$env:ENVIRONMENT_NAME/secrets/$repoSecret"" -Headers $targetHeaders -Method ""PUT"" -Body $bodyJson
          }}
        env:
          ALL_SECRETS: ${{{{ toJSON(secrets) }}}}
          TARGET_PAT: ${{{{ secrets.SECRETS_MIGRATOR_PAT }}}}
          TARGET_ORG: '{targetOrg}'
          TARGET_REPO: '{targetRepo}'
          SOURCE_PAT: ${{{{ secrets.SECRETS_MIGRATOR_SOURCEPAT }}}}
          SOURCE_ORG: '{sourceOrg}'
          SOURCE_REPO: '{sourceRepo}'
          ENVIRONMENT_NAME: '{environment.Name}'
          ENVIRONMENT_ID: '{environment.Id}'
        shell: pwsh
";

  jobs.Add(environment.Name);
}


output = output + $@"
  cleanup:
    runs-on: windows-latest
    if: ${{{{ always() }}}}
    needs: [ {ConvertToCommaSeparated(jobs)} ]
    steps:
      - name: Clean up
        run: |
          $sourcePat = $env:SOURCE_PAT


          $sourceHeaders = @{{
            ""Accept"" = ""application/vnd.github+json""
            ""Authorization"" = ""Bearer $sourcePat""
            ""X-GitHub-Api-Version"" = ""2022-11-28""
          }}

          Write-Output ""Cleaning up...""
          Write-Output ""https://api.github.com/repos/${{{{ github.repository }}}}/git/${{{{ github.ref }}}}""
          Invoke-RestMethod -Uri ""https://api.github.com/repos/${{{{ github.repository }}}}/git/${{{{ github.ref }}}}"" -Method ""DELETE"" -Headers $sourceHeaders
          Invoke-RestMethod -Uri ""https://api.github.com/repos/${{{{ github.repository }}}}/actions/secrets/SECRETS_MIGRATOR_PAT"" -Method ""DELETE"" -Headers $sourceHeaders
          Invoke-RestMethod -Uri ""https://api.github.com/repos/${{{{ github.repository }}}}/actions/secrets/SECRETS_MIGRATOR_SOURCEPAT"" -Method ""DELETE"" -Headers $sourceHeaders
        env:
          SOURCE_PAT: ${{{{ secrets.SECRETS_MIGRATOR_SOURCEPAT }}}}
        shell: pwsh
";
            return output;
        }
    }
}

Set-ExecutionPolicy -Force RemoteSigned -Scope CurrentUser
$autopilotcheck = Read-Host -Prompt "`nAre you on an autopilot device? (Y/N)"

switch ($autopilotcheck)
{
  'y'  { New-PSDrive -Name AD -PSProvider ActiveDirectory -Server "corp.waters.com" -Scope Global -Root "//RootDSE/" -ErrorAction SilentlyContinue
Set-Location AD: 
DIR | Out-Null }

   'n' {Import-Module activedirectory
         continue }
}

:labelA Do {
$username = read-host -prompt "`nType a Username"
Get-ADUser -identity $username -properties "SamAccountName", "UserPrincipalName", "EmailAddress", "Name", "LockedOut", "Enabled", "AccountExpirationDate", "PasswordExpired", "PasswordLastSet", "badPwdCount", "BadLogonCount", "CanonicalName", "Office", "Country", "Description", "Department", "Manager", "Created", "mail", "mailNickname", "DisplayName","extensionAttribute7", "targetAddress", "proxyAddresses" -server corp.waters.com | Select-Object "SamAccountName", "UserPrincipalName", "EmailAddress", "Name", "LockedOut", "Enabled", "AccountExpirationDate", "PasswordExpired", "PasswordLastSet", "badPwdCount", "BadLogonCount", "CanonicalName", "Office", "Country", "Description", "Department", "Manager", "Created", "mail", "mailNickname", "DisplayName", "extensionAttribute7", "targetAddress", "proxyAddresses"
echo @' 
Current Groups:
--------------- 
'@
get-adprincipalgroupmembership -identity ($username) | select -expand name | Sort-Object Name


function Show-Menu
{
    echo "`n==============================`n"
    echo "1: Unlock account"
    echo "2: Reset password"
    echo "3: Add to a group"
    echo "4: Extend account"
    echo "5: Query users & groups by name"
    echo "6: Move this user to an OU"
    echo "F: Enter new username"
    echo "Q: Quit"
}


function Sub-Menu
{
    
    echo "`n1: Query users"
    echo "2: Query groups"
}



Do
{
Show-Menu
$select = Read-Host "`nSelect Option"

switch ($select)
{
    '1' { Unlock-ADAccount -Identity $username -Verbose -server corp.waters.com }
     
    '2' { $newpassword = Read-Host -Prompt "Set new password"
          Set-ADAccountPassword -Identity $username -Reset -NewPassword (ConvertTo-SecureString -AsPlainText $newpassword -Force ) -Verbose -server corp.waters.com}
    
    '3' { $groups = Read-Host -Prompt "`nInput a group name"
          Add-ADGroupMember -Identity $groups -Members $username -Verbose -server corp.waters.com}

    '4' { $expirationdate = Read-Host -Prompt "Set expiration date (dd/mm/yyyy)"
          Set-ADAccountExpiration -Identity $username -DateTime $expirationdate -server corp.waters.com}

    '5' { Sub-Menu
          $getkeywords = Read-Host "`nSelect Option"
          
           
          switch ($getkeywords)
          {
         
         '1' { $getgroups2 = Read-Host -Prompt "`nSearch for users by name"
               $keywords2 = $getgroups2 + "*"
               Get-ADUser -Filter "Name -like '*$keywords2*'" -Properties CanonicalName | select Name, SamAccountName, UserPrincipalName, CanonicalName, Enabled | Sort-Object Name | ft } 
            
            
         '2' { $getgroups = Read-Host -Prompt "`nSearch for groups by name"
               $keywords = $getgroups + "*"
               Get-ADGroup -Filter {name -like $keywords} | Select-Object Name }
               
                
               
           }
           }

     '6' { $searchou = read-host "`nYou will need the OU's GUID or Distinguished Name. Search for OU? (Y/N)"
     echo "Note: The 'Users' DN is: CN=Users,DC=corp,DC=waters,DC=com"
           

            switch ($searchou)
            {
     
            'y' { $ouname = Read-Host -Prompt "`nType OU name"
                  $oukeyword = $ouname + "*"
                  Get-ADOrganizationalUnit -Filter "Name -like '*$oukeyword*'" | select Name, DistinguishedName, ObjectGUID | ft -AutoSize -Wrap
                  $accountname = Get-ADUser -Identity $username
                  $targetOU = Read-Host -Prompt "`nPlease paste the OU GUID or Distinguished Name"
                  
                  $accountname | Move-ADObject -TargetPath $targetOU -Verbose }

            'n' { $accountname = Get-ADUser -Identity $username
                  $targetOU = Read-Host -Prompt "`nPlease paste the OU GUID or Distinguished Name"
                  $accountname | Move-ADObject -TargetPath $targetOU -Verbose}


            }

        }
                                                                                                                             
            


    'f' { continue labelA }

    'q' { return clear-host }
      
}
Pause

}
until ($select -eq 'q') 
    
}
while ($select -eq 'f')




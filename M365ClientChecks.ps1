#######################################################################################################
#                                                                                                     #
# Use this script at your own risk.                                                                   #
# Read, test and understand all of the code using a test account before putting it into production    #
#                                                                                                     #
# Developed and maintined by Ian Waters for the blog: www.SlashAdmin.co.uk                            #
#                                                                                                     #
#######################################################################################################

#Script email notification settings
$notificationToEmailAddress = ""
$notificationFromEmailAddress = ""
$smtpServer = "smtp.office365.com"
$smtpPort = "587"

#Script will only run on tenants in this list
$enabledCustomers = @("", "")

#Authorised email forwarders
$authorisedForwarders = @{}
$authorisedForwarders.Add("","")

#Banned words in emails (Causes email to be deleted when received)
$bannedWords = @("")

#Excluded global display name rule banner addresses
$excludedGlobalDisplayNameSenders = @("","")

#Excluded tenant specific display name rule banner addresses
$excludedDisplayNameSenders =  @{}

#Authorised global admins
$authorisedGlobalAdmins = @("")

#Excluded tenants from global IMAP disable (stops the script from disabling IMAP for the specified tenants)
$excludedIMAPTenants = @("")

#Excluded uses from user level IMAP disable (stops the script from disabling IMAP for the specified user accounts)
$excludedIMAPUsers = @("")

#Excluded tenants from global POP disable (stops the script from disabling POP for the specified tenants)
$excludedPOPTenants = @("")

#Excluded users from user level POP disable (stops the script from disabling POP for the specified user accounts)
$excludedPOPUsers = @("")

function Send-Email([string]$subject, [string]$alertMessage)
{
    $body = "
    <div>
    <p>
    <br/>
    $alertMessage
    <br/>
    </p>
    </div>"

    Send-MailMessage -From $notificationFromEmailAddress -to $notificationToEmailAddress -Subject $subject -Body $body -BodyAsHtml -SmtpServer $smtpServer -port $smtpPort -UseSsl -Credential $credential
}

function Check-Forwarders
{
    Write-Output "Checking forwarders"

    $mailboxes = Get-Mailbox -ResultSize Unlimited
    $domains   = Get-AcceptedDomain
  
    foreach ($mailbox in $mailboxes) 
    {
        $forwardingSMTPAddress = $null
        $forwardingSMTPAddress = $mailbox.forwardingsmtpaddress
        $externalRecipient = $null
        
        if ($forwardingSMTPAddress) 
        {
            $email = ($forwardingSMTPAddress -split "SMTP:")[1]
            $domain = ($email -split "@")[1]
            
            if ($domains.DomainName -notcontains $domain) 
            {
                $externalRecipient = $email
            }
  
            if ($externalRecipient) 
            {
                $whiteListEntry = $authorisedForwarders[$mailbox.primarysmtpaddress]

                if($whiteListEntry -eq $externalRecipient)
                {
                    Write-Output "$externalRecipient has been white listed for $($mailbox.primarysmtpaddress)"
                }
                else
                {
                    Write-Output "External forward $externalRecipient has been detected in account $($mailbox.primarysmtpaddress)"
                    Send-Email "Office 365 Email Forwarder Detected"  "We have detected a new email forwarder to an external recipient in Office 365</br></br>$($mailbox.displayname) - $($mailbox.primarysmtpaddress) forwards to $externalRecipient"
                }
            }
        }
    }

    Write-Output "Finished checking forwarders"
}

function Enable-BannedWordsRule
{
    Write-Output "Checking for banned words rule"

    $ruleName = "Delete email when it contains specified words"
    $transportRule = Get-TransportRule | Where-Object {$_.Identity -contains $ruleName}

    if (!$transportRule) 
    {
        Write-Output "Rule not found, creating Rule"
        $result = New-TransportRule -Name $ruleName -Priority 0 -FromScope "NotInOrganization"  -SubjectOrBodyContainsWords $bannedWords -DeleteMessage $true
    }
    else 
    {
        Write-Output "Rule found, updating Rule"
        $result = Set-TransportRule -Identity $ruleName -Priority 0 -FromScope "NotInOrganization"  -SubjectOrBodyContainsWords $bannedWords -DeleteMessage $true
    }

    Write-Output "Finished checking for banned words rule"
}

function Check-GlobalAdmins([string]$tenantID)
{
    Write-Output "Checking for Global Admins"

    $globalAdminRole = Get-MsolRole -RoleName "Company Administrator" -TenantId $tenantID
    $globalAdmins    = Get-MsolRoleMember -RoleObjectId $globalAdminRole.ObjectId -TenantId $tenantID
    $unauthorisedGlobalAdmins = $globalAdmins | where-object {$_.EmailAddress -notin $authorisedGlobalAdmins -and $_.RoleMemberType -eq "User"}

    if($unauthorisedGlobalAdmins.Count -gt 0)
    {
        $companyName = (Get-MsolCompanyInformation -TenantId $tenantID).DisplayName

        Write-Output "Unauthorised Global admins have been detected:"
        
        $unauthorisedGAList = ""
        foreach($admin in $unauthorisedGlobalAdmins)
        {
            Write-Output $admin.EmailAddress
            $unauthorisedGAList += "</br>$($admin.EmailAddress)"
        }
                  
        Send-Email "Office 365 Global Admin Detected"  "We have detected a new Global Admin in Office 365 tenant: $companyName $($unauthorisedGAList)</br>"
    }

    Write-Output "Finished checking for Global Admins"
}

function Enable-DisplayNameRule([string]$tenantID)
{
    Write-Output "Checking for Display name rule"

    $companyName = (Get-MsolCompanyInformation -TenantId $tenantID).DisplayName
    
    $ruleName = "Warn on external senders with matching internal display names"
    $ruleHtml = "<table class=MsoNormalTable border=0 cellspacing=0 cellpadding=0 align=left width=`"100%`" style='width:100.0%;mso-cellspacing:0cm;mso-yfti-tbllook:1184; mso-table-lspace:2.25pt;mso-table-rspace:2.25pt;mso-table-anchor-vertical:paragraph;mso-table-anchor-horizontal:column;mso-table-left:left;mso-padding-alt:0cm 0cm 0cm 0cm'>  <tr style='mso-yfti-irow:0;mso-yfti-firstrow:yes;mso-yfti-lastrow:yes'><td style='background:#910A19;padding:5.25pt 1.5pt 5.25pt 1.5pt'></td><td width=`"100%`" style='width:100.0%;background:#FDF2F4;padding:5.25pt 3.75pt 5.25pt 11.25pt; word-wrap:break-word' cellpadding=`"7px 5px 7px 15px`" color=`"#212121`"><div><p class=MsoNormal style='mso-element:frame;mso-element-frame-hspace:2.25pt; mso-element-wrap:around;mso-element-anchor-vertical:paragraph;mso-element-anchor-horizontal: column;mso-height-rule:exactly'><span style='font-size:9.0pt;font-family: `"Segoe UI`",sans-serif;mso-fareast-font-family:`"Times New Roman`";color:#212121'>This message was sent from outside the company by someone with a display name matching a user in your organisation. Please do not click links or open attachments unless you recognise the source of this email and know the content is safe. <o:p></o:p></span></p></div></td></tr></table>"
 
    $transportRule = Get-TransportRule | Where-Object {$_.Identity -contains $ruleName}
    $displayNames = (Get-Mailbox -ResultSize Unlimited).DisplayName
    
    #build list of email addresses excluded from the rule
    $excludedSenders = $excludedGlobalDisplayNameSenders + $excludedDisplayNameSenders[$companyName]
    
    if (!$transportRule) 
    {
        Write-Output "Rule not found, creating Rule"
        $result = New-TransportRule -Name $ruleName -Priority 0 -FromScope "NotInOrganization" -ApplyHtmlDisclaimerLocation "Prepend" -HeaderMatchesMessageHeader From -HeaderMatchesPatterns $displayNames -ApplyHtmlDisclaimerText $ruleHtml -ExceptIfFrom $excludedSenders
    }
    else 
    {
        Write-Output "Rule found, updating Rule"
        $result = Set-TransportRule -Identity $ruleName -Priority 0 -FromScope "NotInOrganization" -ApplyHtmlDisclaimerLocation "Prepend" -HeaderMatchesMessageHeader From -HeaderMatchesPatterns $displayNames -ApplyHtmlDisclaimerText $ruleHtml -ExceptIfFrom $excludedSenders
    }

    Write-Output "Finished checking for Display name rule"
}

function Disable-IMAPTenantLevel([string]$tenantID)
{
    Write-Output "Disabling IMAP at tenant level"
    
    $companyName = (Get-MsolCompanyInformation -TenantId $tenantID).DisplayName

    if($companyName -in $excludedIMAPTenants)
    {
        Write-Output "Tenant is authorised for IMAP"
    }
    else
    {
        Get-CASMailboxPlan -Filter {ImapEnabled -eq "true"} | set-CASMailboxPlan -ImapEnabled $false
    
        $checkPlan = Get-CASMailboxPlan -Filter {ImapEnabled -eq "false"}
    
        if ($checkPlan) 
        {
            Write-Output "IMAP now disabled"
        }
        else 
        {
            Write-Output "There was a problem disabling IMAP"
            #Send-Email "Office 365 Disable IMAP Issue"  "We have had a problem disabling IMAP for Office365 tenant: $companyName"
        }
    }

    Write-Output "Finished disabling IMAP at tenant level"
}

function Disable-IMAPExistingMailboxes
{
    Write-Output "Disable IMAP for existing mailboxes"

    $imapEnabledMailboxes = Get-CASMailbox -Filter {ImapEnabled -eq "true"}

    foreach($mailbox in $imapEnabledMailboxes)
    {
        if($mailbox.primarysmtpaddress -notin $excludedIMAPUsers)
        {
            $result = Set-CASMailbox -ImapEnabled $false -Identity $mailbox.primarysmtpaddress

            Write-Output "User: $($mailbox.primarysmtpaddress) IMAP Disabled"
        }
        else
        {
            Write-Output "User: $($mailbox.primarysmtpaddress) is authorised for IMAP"
        }
    }

    Write-Output "Finished disabling IMAP for existing users"
}

function Disable-POPTenantLevel([string]$tenantID)
{
    Write-Output "Disabling POP at tenant level"
    
    $companyName = (Get-MsolCompanyInformation -TenantId $tenantID).DisplayName

    if($companyName -in $excludedPOPTenants)
    {
        Write-Output "Tenant is authorised for POP"
    }
    else
    {
        Get-CASMailboxPlan -Filter {PopEnabled -eq "true"} | set-CASMailboxPlan -PopEnabled $false
    
        $checkPlan = Get-CASMailboxPlan -Filter {PopEnabled -eq "false"}
    
        if ($checkPlan) 
        {
            Write-Output "POP now disabled"
        }
        else 
        {
            Write-Output "There was a problem disabling POP"
            #Send-Email "Office 365 Disable POP Issue"  "We have had a problem disabling POP for Office365 tenant: $companyName"
        }
    }

    Write-Output "Finished disabling POP at tenant level"
}

function Disable-POPExistingMailboxes
{
    Write-Output "Disable POP for existing mailboxes"

    $popEnabledMailboxes = Get-CASMailbox -Filter {PopEnabled -eq "true"}

    foreach($mailbox in $popEnabledMailboxes)
    {
        if($mailbox.primarysmtpaddress -notin $excludedPOPUsers)
        {
            $result = Set-CASMailbox -PopEnabled $false -Identity $mailbox.primarysmtpaddress

            Write-Output "User: $($mailbox.primarysmtpaddress) POP Disabled"
        }
        else
        {
            Write-Output "User: $($mailbox.primarysmtpaddress) is authorised for POP"
        }
    }

    Write-Output "Finished disabling POP for existing users"
}

function Disable-JunkFolders
{
    Write-Output "Disable junk folder for existing mailboxes"

    $result = Get-Mailbox -ResultSize unlimited -RecipientTypeDetails UserMailbox; $result | foreach {Set-MailboxJunkEmailConfiguration -Identity $_.UserPrincipalName –Enabled $False} | Where {$_.Enabled -eq $true}
        
    Write-Output "Finished disabling junk folder for existing users"
}

function Enable-AdminAuditLogs
{
    Write-Output "Enabling admin audit logs"
    
    $auditLogConfig = Get-AdminAuditLogConfig 

    Write-Output "Admin audit enabled: $($auditLogConfig.AdminAuditLogEnabled)"

    if($auditLogConfig.AdminAuditLogEnabled -eq $false)
    {
        Write-Host "Enabling Admin Audit Log"
        Set-AdminAuditLogConfig -AdminAuditLogEnabled $true
    }

    Write-Output "Unified audit enabled: $($auditLogConfig.UnifiedAuditLogIngestionEnabled)"

    if($auditLogConfig.UnifiedAuditLogIngestionEnabled -eq $false)
    {
        Write-Host "Enabling Unified Audit Log"
        Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true
    }
         
    Write-Output "Finished enabling admin audit logs"
}

function Check-LicensedAdmins([string]$tenantID)
{
    Write-Output "Checking for licensed CloudAdmins"
    
    $admin = Get-MsolUser -SearchString "cloudadmin" -TenantId $tenantID | Where-Object {($_.licenses).AccountSkuId -match "ENTERPRISEPACK"}
          
    if($admin -ne $null)
    {
        Write-Host "FOUND LICENSED ADMIN" $admin.UserPrincipalName              
        Send-Email "Office 365 Licensed Admin Detected"  "We have detected a licensed admin $($admin.UserPrincipalName) in tenant: $companyName $($unauthorisedGAList)</br>"
    }

    Write-Output "Finished checking for licensed CloudAdmins"
}
##################################################################################################################

#Connect to 365
$credential = Get-AutomationPSCredential -Name "365 Cloudadmin"
Connect-MsolService -Credential $credential

#Get customers and partner information
$customers = Get-MsolPartnerContract -All
$partnerInfo = Get-MsolCompanyInformation

Write-Output "Found $($customers.Count) customers for $($partnerInfo.DisplayName)"
 
foreach ($customer in $customers) 
{ 
    Write-Output "-----------------------------------------------"
    Write-Output "Customer Name: [$($customer.Name)]"
    
    if($customer.Name -in $enabledCustomers)
    {
        Write-Output "Starting Tenant Check of: $($customer.Name)"
        
        #Connect session to customers tenant
        $initialDomain = Get-MsolDomain -TenantId $customer.TenantId | Where-Object {$_.IsInitial}
        $delegatedURL = "https://ps.outlook.com/powershell?DelegatedOrg=" + $initialDomain.Name
        $psSession = New-PSSession -ConnectionUri $delegatedURL -Credential $credential -Authentication Basic -ConfigurationName Microsoft.Exchange -AllowRedirection
                
        Import-PSSession -Session $psSession -DisableNameChecking:$true -AllowClobber:$true | Out-Null
     
        #Run checks
        Enable-AdminAuditLogs
        Check-Forwarders
        Enable-BannedWordsRule
        Check-GlobalAdmins $customer.TenantId
        Enable-DisplayNameRule $customer.TenantId
        Disable-IMAPTenantLevel $customer.TenantId
        Disable-IMAPExistingMailboxes
        Disable-POPTenantLevel $customer.TenantId
        Disable-POPExistingMailboxes
        Disable-JunkFolders
        Check-LicensedAdmins $customer.TenantId
        
        #Disconnect session from customers tenant
        Remove-PSSession $psSession

        Write-Output "Finished Tenant Check of: $($customer.Name)"
    }
    else
    {
        Write-Output "Customer excluded from checks"
    }
}

import subprocess
import logging

logger = logging.getLogger(__name__)

class ADUtils:
    MOCK_MODE = False

    @staticmethod
    def check_requirements():
        """Checks if the ActiveDirectory module is available."""
        if ADUtils.MOCK_MODE:
            return True
        
        # Try to import module if not present (helps in some shell encironments)
        ADUtils.run_ps_command("Import-Module ActiveDirectory")
        
        success, out, _ = ADUtils.run_ps_command("Get-Module -ListAvailable ActiveDirectory")
        return success and "ActiveDirectory" in out

    @staticmethod
    def run_ps_command(command):
        """Runs a PowerShell command and returns the output/error."""
        if ADUtils.MOCK_MODE:
             logging.info(f"[MOCK] Executing: {command}")
             return True, "Mock Success", ""

        try:
            # -NonInteractive -NoProfile to avoid hanging
            full_command = ["powershell", "-NonInteractive", "-NoProfile", "-Command", command]
            result = subprocess.run(
                full_command,
                capture_output=True,
                text=True,
                check=False # Don't raise immediately, we handle returncode
            )
            return result.returncode == 0, result.stdout, result.stderr
        except Exception as e:
            logger.error(f"Failed to execute PowerShell command: {e}")
            return False, "", str(e)

    @staticmethod
    def create_user(username, password, description=""):
        """Creates a new AD User."""
        # Note: Password handling in AD usually requires ConvertTo-SecureString
        # This is a basic template. Secure string handling is tricky via simple CLI without passing cleartext.
        # For a simplified tool, we might assume policies allow standard setting or we construct the SecureString object.
        
        # CAUTION: Passing password in command line is visible in process audit.
        # Ideally we use input streams, but for this prototype we'll keep it simple.
        
        cmd = f"""
        $sec_pass = ConvertTo-SecureString '{password}' -AsPlainText -Force;
        New-ADUser -Name '{username}' -AccountPassword $sec_pass -Enabled $true -Description '{description}'
        """
        return ADUtils.run_ps_command(cmd)

    @staticmethod
    def remove_user(username):
        """Removes an AD User."""
        cmd = f"Remove-ADUser -Identity '{username}' -Confirm:$false"
        return ADUtils.run_ps_command(cmd)
        
    @staticmethod
    def add_to_group(username, group_name):
        """Adds a user to a group."""
        cmd = f"Add-ADGroupMember -Identity '{group_name}' -Members '{username}'"
        return ADUtils.run_ps_command(cmd)

    @staticmethod
    def reset_password(username, new_password):
        """Resets a user's password."""
        cmd = f"""
        $sec_pass = ConvertTo-SecureString '{new_password}' -AsPlainText -Force;
        Set-ADAccountPassword -Identity '{username}' -NewPassword $sec_pass -Reset $true
        """
        return ADUtils.run_ps_command(cmd)

    @staticmethod
    def get_all_users_and_groups():
        """Retrieves all AD users and their groups."""
        if ADUtils.MOCK_MODE:
            return True, '[{"Name": "Administrator", "Groups": "Administrators, Domain Admins"}, {"Name": "Guest", "Groups": "Domain Guests"}, {"Name": "JohnDoe", "Groups": "Finance, Employees"}]', ""
        
        cmd = """
        Get-ADUser -Filter * -Properties MemberOf | Select-Object Name, @{Name="Groups";Expression={ ($_.MemberOf | ForEach-Object { ($_ -split ",")[0] -replace "CN=","" }) -join ", " }} | ConvertTo-Json -Compress
        """
        return ADUtils.run_ps_command(cmd)

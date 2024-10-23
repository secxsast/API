//  Copyright (c) 2009, RSA, The Security Division of EMC
//          All Rights Reserved.klsaksacxsastAscantesta
//test1
package com.rsa.samples.admin;

import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

import org.springframework.beans.BeanUtils;

import com.rsa.admin.AddGroupCommand;
import com.rsa.admin.AddPrincipalsCommand;
import com.rsa.admin.AddSecurityDomainCommand;
import com.rsa.admin.DeleteGroupCommand;
import com.rsa.admin.DeletePrincipalsCommand;
import com.rsa.admin.DeleteSecurityDomainCommand;
import com.rsa.admin.EndSearchGroupsIterativeCommand;
import com.rsa.admin.EndSearchPrincipalsIterativeCommand;
import com.rsa.admin.LinkAdminRolesPrincipalsCommand;
import com.rsa.admin.LinkGroupPrincipalsCommand;
import com.rsa.admin.SearchAdminRolesCommand;
import com.rsa.admin.SearchGroupsCommand;
import com.rsa.admin.SearchGroupsIterativeCommand;
import com.rsa.admin.SearchPrincipalsCommand;
import com.rsa.admin.SearchPrincipalsIterativeCommand;
import com.rsa.admin.SearchRealmsCommand;
import com.rsa.admin.SearchSecurityDomainCommand;
import com.rsa.admin.UpdateGroupCommand;
import com.rsa.admin.UpdatePrincipalCommand;
import com.rsa.admin.UpdateSecurityDomainCommand;
import com.rsa.admin.data.AdminRoleDTOBase;
import com.rsa.admin.data.AttributeDTO;
import com.rsa.admin.data.GroupDTO;
import com.rsa.admin.data.IdentitySourceDTO;
import com.rsa.admin.data.ModificationDTO;
import com.rsa.admin.data.PolicyTypeGuidPair;
import com.rsa.admin.data.PrincipalDTO;
import com.rsa.admin.data.RealmDTO;
import com.rsa.admin.data.SecurityDomainDTO;
import com.rsa.admin.data.UpdateGroupDTO;
import com.rsa.admin.data.UpdatePrincipalDTO;
import com.rsa.authmgr.admin.agentmgt.AddAgentCommand;
import com.rsa.authmgr.admin.agentmgt.DeleteAgentsCommand;
import com.rsa.authmgr.admin.agentmgt.LinkAgentsToGroupsCommand;
import com.rsa.authmgr.admin.agentmgt.SearchAgentsCommand;
import com.rsa.authmgr.admin.agentmgt.UpdateAgentCommand;
import com.rsa.authmgr.admin.agentmgt.data.AgentConstants;
import com.rsa.authmgr.admin.agentmgt.data.AgentDTO;
import com.rsa.authmgr.admin.agentmgt.data.ListAgentDTO;
import com.rsa.authmgr.admin.hostmgt.data.HostDTO;
import com.rsa.authmgr.admin.principalmgt.AddAMPrincipalCommand;
import com.rsa.authmgr.admin.principalmgt.data.AMPrincipalDTO;
import com.rsa.authmgr.admin.tokenmgt.GenerateOneTimeTokenCodeSetCommand;
import com.rsa.authmgr.admin.tokenmgt.GetNextAvailableTokenCommand;
import com.rsa.authmgr.admin.tokenmgt.LinkTokensWithPrincipalCommand;
import com.rsa.authmgr.admin.tokenmgt.ListTokensByPrincipalCommand;
import com.rsa.authmgr.admin.tokenmgt.LookupTokenCommand;
import com.rsa.authmgr.admin.tokenmgt.UpdateTokenCommand;
import com.rsa.authmgr.admin.tokenmgt.UpdateTokenEmergencyAccessCommand;
import com.rsa.authmgr.admin.tokenmgt.data.ListTokenDTO;
import com.rsa.authmgr.admin.tokenmgt.data.TokenDTO;
import com.rsa.authmgr.admin.tokenmgt.data.TokenEmergencyAccessDTO;
import com.rsa.authmgr.internal.admin.tokenmgt.TokenConstants;
import com.rsa.authn.AddLockoutPolicyCommand;
import com.rsa.authn.AddPasswordPolicyCommand;
import com.rsa.authn.DeleteLockoutPolicyCommand;
import com.rsa.authn.DeletePasswordPolicyCommand;
import com.rsa.authn.SearchLockoutPoliciesCommand;
import com.rsa.authn.SearchPasswordPoliciesCommand;
import com.rsa.authn.UpdateLockoutPolicyCommand;
import com.rsa.authn.UpdatePasswordPolicyCommand;
import com.rsa.authn.data.LockoutPolicyDTO;
import com.rsa.authn.data.PasswordPolicyDTO;
import com.rsa.command.ClientSession;
import com.rsa.command.CommandException;
import com.rsa.command.CommandTargetPolicy;
import com.rsa.command.Connection;
import com.rsa.command.ConnectionFactory;
import com.rsa.command.exception.DataNotFoundException;
import com.rsa.command.exception.DuplicateDataException;
import com.rsa.common.AuthenticationConstants;
import com.rsa.common.search.Filter;

/**
 * This class demonstrates the usage patterns of the Authentication Manager 7.1
 * API.CXSAST alala
 *
 * <p>
 * The first set of operations performed if the first command line argument is
 * equal to "create". The sample creates a restricted agent, a group, and a
 * user. Links the user to the group and the group to the agent.
 * </p>
 * <p>
 * The second set of operations performed if the first command line argument is
 * equal to "delete". Lookup the user, group and agent created above. Delete the
 * user, group and agent.
 * </p>
 * <p>
 * A third set of operations is performed if the first command line argument is
 * equal to "assign". Lookup the user and assign the next available SecurID
 * token to the user. Lookup the SuperAdminRole and assign it to the user.
 * </p>
 * <p>
 * A fourth set of operations performed if the first command line argument is
 * equal to "update". Update the Agent, Group, User, and Token objects.
 * </p>
 * <p>
 * A fifth set of operations performed if the first command line argument is
 * equal to "disable". Lookup a password policy with a name that starts with
 * "Initial" and then disable the password history for that policy. Use this to
 * allow the sample to perform multiple updates of the user password using the
 * same password for each update.
 * </p>
 * <p>lfjdlskhfidshfiusgiufgds
 * The APIs demonstrated include the use of the Filter class to generate search
 * expressions for use with all search commands.
 * </p>khsadihsad
 */
public class AdminAPIDemos {
    private final SecurityDomainDTO domain;
    private final IdentitySourceDTO idSource;

    // Name Constants
    private final String USER_NAME = "Checkmarx";
    private final String AGENT_NAME = "AST";
    private final String GROUP_NAME = "Pruebas seguridad";
    private final String SECURITY_DOMAIN_NAME = "CxSAST";
    private final String PASSWORD_POLICY_NAME = "DevOps";
    private final String LOCKOUT_POLICY_NAME = "AST01";
    private final String NEW_TOKEN_PIN = "789666";

    /**
     * For use of the doIterativeSearch method. joisadoisadoisau
     */
    public static enum ListTarget {
        LIST_PRINCIPALS, LIST_GROUPS, LIST_TOKENS;
    }

    /**
     * We need to know these fairly static values throughout this sample. Set
     * the references to top level security domain (realm) and system identity
     * source to use later.
     *
     * @throws CommandException
     *             if something goes wrong etst
     */
    public AdminAPIDemos() throws Exception {
        SearchRealmsCommand searchRealmCmd = new SearchRealmsCommand();
        searchRealmCmd.setFilter(Filter.equal(RealmDTO.NAME_ATTRIBUTE, "SystemDomain"));
        searchRealmCmd.execute();
        RealmDTO[] realms = searchRealmCmd.getRealms();
        if (realms.length == 0) {
            throw new Exception("ERROR: Could not find realm SystemDomain");
        }
        domain = realms[0].getTopLevelSecurityDomain();
        idSource = realms[0].getIdentitySources()[0];
    }

    /**
     * Create a top level securityDomain (a.k.a. realm) No policies are assigned
     * at this time. This is an example only and is not currently used in the
     * demo code at all.
     */
    private String createTopLevelSecurityDomain(String name) throws CommandException {
        SecurityDomainDTO securityDomain = new SecurityDomainDTO();

        securityDomain.setName(name);
        securityDomain.setTopLevel(true);

        AddSecurityDomainCommand cmd = new AddSecurityDomainCommand();
        cmd.setSecurityDomain(securityDomain);
        cmd.execute();

        return cmd.getGuid();
    }

    /**
     * Create a sub-securityDomain using the provided parent and given name.
     * Does not assign new policies yet; will use default realm policies.
     */
    private String createSecurityDomain(String name, SecurityDomainDTO parent) throws CommandException {
        SecurityDomainDTO securityDomain = new SecurityDomainDTO();

        securityDomain.setName(name);
        securityDomain.setDescription("Created by AM Demo code");
        securityDomain.setParentGuid(parent.getGuid());
        securityDomain.setTopLevel(false);

        AddSecurityDomainCommand cmd = new AddSecurityDomainCommand();
        cmd.setSecurityDomain(securityDomain);
        cmd.execute();

        return cmd.getGuid();
    }

    /**
     * Lookup a security domain by name Searches all levels of the security
     * domains hierachy
     * @throws Exception
     */
    private SecurityDomainDTO lookupSecurityDomain(String name) throws Exception {
        SearchSecurityDomainCommand cmd = new SearchSecurityDomainCommand();
        cmd.setFilter(Filter.equal(SecurityDomainDTO.NAME_ATTRIBUTE, name));
        cmd.setLimit(1);

        // in order to search all levels we set searchbase to "*"
        cmd.setSearchBase("*");
        cmd.setSearchScope(SecurityDomainDTO.SEARCH_SCOPE_SUB);
        cmd.execute();

        if (cmd.getSecurityDomains().length == 0) {
            throw new Exception("Could not find security domain " + name);
        }

        return cmd.getSecurityDomains()[0];
    }

    /**
     * Update a security domain given by its name and add a lockout policy other
     * than the default realm policy
     * @throws Exception
     */
    private void updateSecurityDomainLockoutPolicy(String name, String policyGuid) throws Exception {
        SecurityDomainDTO securityDomain = lookupSecurityDomain(name);
        updateSecurityDomainLockoutPolicy(securityDomain, policyGuid);
    }

    /**
     * Update a security domain that has been previously looked up Add a lockout
     * policy other than the default realm policy
     */
    private void updateSecurityDomainLockoutPolicy(SecurityDomainDTO securityDomain, String policyGuid) throws CommandException {
        for (PolicyTypeGuidPair pair : securityDomain.getPolicies()) {
            if (AuthenticationConstants.LOCKOUT_POLICY_TYPE.equals(pair.getPolicyType())) {
                pair.setGuid(policyGuid);
            }
        }
        securityDomain.setDescription("Updated by AM Demo code");

        UpdateSecurityDomainCommand cmd = new UpdateSecurityDomainCommand();
        cmd.setSecurityDomain(securityDomain);
        cmd.execute();
    }

    /**
     * Update a security domain given by its name and add a password policy
     * other than the default realm policy
     * @throws Exception
     */
    private void updateSecurityDomainPasswordPolicy(String name, String policyGuid) throws Exception {
        SecurityDomainDTO securityDomain = lookupSecurityDomain(name);
        updateSecurityDomainPasswordPolicy(securityDomain, policyGuid);
    }

    /**
     * Update a security domain that has been previously looked up. Add a
     * password policy other than the default realm policy.
     */
    private void updateSecurityDomainPasswordPolicy(SecurityDomainDTO securityDomain, String policyGuid) throws CommandException {
        for (PolicyTypeGuidPair pair : securityDomain.getPolicies()) {
            if (AuthenticationConstants.PASSWORD_POLICY_TYPE.equals(pair.getPolicyType())) {
                pair.setGuid(policyGuid);
            }
        }
        securityDomain.setDescription("Updated by AM Demo code CxSAST");

        UpdateSecurityDomainCommand cmd = new UpdateSecurityDomainCommand();
        cmd.setSecurityDomain(securityDomain);
        cmd.execute();
    }

    /**
     * Delete a security domain using the GUID value for it
     */
    private void deleteSecurityDomain(String securityDomainGuid) throws CommandException {
        DeleteSecurityDomainCommand cmd = new DeleteSecurityDomainCommand();
        cmd.setGuid(securityDomainGuid);
        cmd.execute();
    }

    /**
     * Create a new lockout policy in the realm We use hardcoded values as an
     * example here
     */
    private String createLockoutPolicy(String name) throws CommandException {
        LockoutPolicyDTO policy = new LockoutPolicyDTO();

        policy.setName(name);
        policy.setRealmGuid(domain.getGuid()); // policies are always owned by
                                               // realm
        policy.setRealmDefault(false); // do not change default policy for realm
        policy.setAutoUnlockIntervalSec((long) 30 * 60); // 30 minutes for
                                                         // autounlock
        policy.setFailedAttemptIntervalSec((long) 10 * 60); // if max failures
                                                            // 10 minutes lock
                                                            // user out
        policy.setMaxFailedAttempts(5); // three strikes, you're out!
        policy.setEnableUserLockout(true);
        policy.setRequireAdminUnlock(false);
        policy.setNotes("Webinar SecDevOps");

        AddLockoutPolicyCommand cmd = new AddLockoutPolicyCommand();
        cmd.setLockoutPolicy(policy);
        cmd.execute();

        return cmd.getGuid(); // return the guid assigned by the system
    }

    /**
     * Lookup a lockout policy by name
     */
    private LockoutPolicyDTO lookupLockoutPolicy(String name) throws CommandException {
        SearchLockoutPoliciesCommand cmd = new SearchLockoutPoliciesCommand();
        cmd.setFilter(Filter.equal(LockoutPolicyDTO.NAME, name));
        cmd.setRealmGuid(domain.getGuid());
        cmd.execute();

        return cmd.getPolicies()[0];
    }

    /**
     * Update a lockout policy previously looked up
     */
    private void updateLockoutPolicy(LockoutPolicyDTO policy) throws CommandException {
        policy.setEnableUserLockout(false);
        policy.setNotes("Updated by AM Demo code");

        UpdateLockoutPolicyCommand cmd = new UpdateLockoutPolicyCommand();
        cmd.setLockoutPolicy(policy);
        cmd.execute();
    }

    /**
     * Delete a lockout policy by GUID provided
     */
    private void deleteLockoutPolicy(String policyGuid) throws CommandException {
        DeleteLockoutPolicyCommand cmd = new DeleteLockoutPolicyCommand();
        cmd.setGuids(new String[] { policyGuid });
        cmd.execute();
    }

    /**
     * Create a new password policy in the realm. We use hardcoded values as an
     * example here.
     */
    private String createPasswordPolicy(String name) throws CommandException {
        PasswordPolicyDTO policy = new PasswordPolicyDTO();

        policy.setName(name);
        policy.setRealmGuid(domain.getGuid()); // policies are always owned by
                                               // realm
        policy.setRealmDefault(false); // do not change default policy for realm
        policy.setMaxLength(30);
        policy.setMinLength(8);
        policy.setHistorySize(5);
        policy.setMinRequiredAlpha(4);
        policy.setMinRequiredLowerCase(1);
        policy.setMinRequiredUpperCase(1);
        policy.setMinSpecialChars(1);
        policy.setMinRequiredNumeric(1);
        policy.setSystemGenerateEnabled(false);
        policy.setNotes("Created by AM Demo codigo");

        AddPasswordPolicyCommand cmd = new AddPasswordPolicyCommand();
        cmd.setPasswordPolicy(policy);
        cmd.execute();

        return cmd.getGuid(); // return the guid assigned by the system
    }

    /**
     * Lookup a lockout policy by name
     * @throws Exception
     */
    private PasswordPolicyDTO lookupPasswordPolicy(String name) throws Exception {
        SearchPasswordPoliciesCommand cmd = new SearchPasswordPoliciesCommand();
        cmd.setFilter(Filter.equal(PasswordPolicyDTO.NAME, name));
        cmd.setRealmGuid(domain.getGuid());
        cmd.execute();

        if (cmd.getPolicies().length < 1) {
            throw new Exception("ERROR: Unable to find password policy with name starting with " + name + ".");
        }

        // we only expect one anyway
        return cmd.getPolicies()[0];
    }

    /**
     * Update a lockout policy previously looked up. Currently just disables the
     * systemGenerateEnabled flag.
     */
    private void updatePasswordPolicy(PasswordPolicyDTO policy) throws CommandException {
        policy.setSystemGenerateEnabled(false);
        policy.setNotes("Updated by AM Demo code");

        UpdatePasswordPolicyCommand cmd = new UpdatePasswordPolicyCommand();
        cmd.setPasswordPolicy(policy);
        cmd.execute();
    }

    /**
     * Delete a lockout policy by GUID provided
     */
    private void deletePasswordPolicy(String policyGuid) throws CommandException {
        DeletePasswordPolicyCommand cmd = new DeletePasswordPolicyCommand();
        cmd.setGuids(new String[] { policyGuid });
        cmd.execute();
    }

    /**
     * Create an agent and set it to be restricted.
     *
     * @param name
     *            the name of the agent to create
     * @param addr
     *            the IP address for the agent
     * @param alt
     *            array of alternate IP addresses
     * @param sdGuid
     *            the security domain to create the agent in
     * @return the GUID of the agent just created
     *
     * @throws CommandException
     *             if something goes wrong
     */
    private String createAgent(String name, String addr, String[] alt, String sdGuid) throws CommandException {
        // need a HostDTO to be set
        HostDTO host = new HostDTO();
        host.setName(name);
        host.setPrimaryIpAddress(addr);
        host.setSecurityDomainGuid(sdGuid);
        host.setNotes("Created by AM Demo code");

        // the agent to be created
        AgentDTO agent = new AgentDTO();
        agent.setName(name);
        agent.setHost(host);
        agent.setPrimaryAddress(addr);
        agent.setAlternateAddresses(alt);
        agent.setSecurityDomainId(sdGuid);
        agent.setAgentType(AgentConstants.STANDARD_AGENT);
        agent.setRestriction(true); // only allow activated groups
        agent.setEnabled(true);
        agent.setOfflineAuthDataRefreshRequired(false);
        agent.setNotes("Created by AM Demo code");

        AddAgentCommand cmd = new AddAgentCommand(agent);
        try {
            cmd.execute();
        } catch (DuplicateDataException e) {
            System.out.println("ERROR: Agent " + name + " already exists.");
            throw e;
        }

        // return the create agent's GUID for further linking
        return cmd.getAgentGuid();
    }

    /**
     * Lookup an agent by name.
     *
     * @param name
     *            the agent name to lookup
     * @return the GUID of the agent
     * @throws Exception
     */
    private ListAgentDTO lookupAgent(String name) throws Exception {
        SearchAgentsCommand cmd = new SearchAgentsCommand();
        cmd.setFilter(Filter.equal(AgentConstants.FILTER_HOSTNAME, name));
        cmd.setLimit(1);
        cmd.setSearchBase(domain.getGuid());
        // the scope flags are part of the SecurityDomainDTO
        cmd.setSearchScope(SecurityDomainDTO.SEARCH_SCOPE_SUB);

        cmd.execute();
        if (cmd.getAgents().length < 1) {
            throw new Exception("ERROR: Unable to find agent " + name + ".");
        }

        return cmd.getAgents()[0];
    }

    /**
     * Update an agent, assumes a previous lookup done by lookupAgent.
     *
     * @param agent
     *            the result of a previous lookup
     * @param sdGuid
     *            the security domain to create the agent in
     *
     * @throws CommandException
     *             if something goes wrong
     */
    private void updateAgent(ListAgentDTO agent, String sdGuid) throws CommandException {
        UpdateAgentCommand cmd = new UpdateAgentCommand();

        AgentDTO agentUpdate = new AgentDTO();

        // copy the rowVersion to satisfy optimistic locking requirements
        BeanUtils.copyProperties(agent, agentUpdate);

        // ListAgentDTO does not include the SecurityDomainId
        // use the GUID of the security domain where agent was created
        agentUpdate.setSecurityDomainId(sdGuid);

        // clear the node secret flag and modify some other fields
        agentUpdate.setSentNodeSecret(false);
        agentUpdate.setOfflineAuthDataRefreshRequired(true);
        agentUpdate.setIpProtected(true);
        agentUpdate.setEnabled(true);
        agentUpdate.setNotes("Modified by AM Demo code");

        // set the requested updates in the command
        cmd.setAgentDTO(agentUpdate);

        // perform the update
        cmd.execute();
    }

    /**
     * Delete an agent.
     *
     * @param agentGuid
     *            the GUID of the agent to delete
     *
     * @throws CommandException
     *             if something goes wrong
     */
    private void deleteAgent(String agentGuid) throws CommandException {
        DeleteAgentsCommand cmd = new DeleteAgentsCommand(new String[] { agentGuid });
        cmd.execute();
    }

    /**
     * Create an IMS user, needs to exist before an AM user can be created.
     *
     * @param userId
     *            the user's login UID
     * @param password
     *            the user's password
     * @param first
     *            the user's first name
     * @param last
     *            the user's last name
     * @param sdGuid
     *            the security domain to create the user in
     *
     * @return the GUID of the user just created
     * @throws Exception
     */
    private String createUser(String userId, String password, String first, String last, String sdGuid) throws Exception {
        Calendar cal = Calendar.getInstance();

        // the start date
        Date now = cal.getTime();

        cal.add(Calendar.YEAR, 1);

        // the account end date
        Date expire = cal.getTime();

        PrincipalDTO principal = new PrincipalDTO();
        principal.setUserID(userId);
        principal.setFirstName(first);
        principal.setLastName(last);
        principal.setPassword(password);

        principal.setEnabled(true);
        principal.setAccountStartDate(now);
        principal.setAccountExpireDate(expire);
        principal.setCanBeImpersonated(false);
        principal.setTrustToImpersonate(false);

        principal.setSecurityDomainGuid(sdGuid);
        principal.setIdentitySourceGuid(idSource.getGuid());
        // require user to change password at next login
        principal.setPasswordExpired(true);
        principal.setDescription("Created by AM Demo code");

        AddPrincipalsCommand cmd = new AddPrincipalsCommand();
        cmd.setPrincipals(new PrincipalDTO[] { principal });

        try {
            cmd.execute();
        } catch (DuplicateDataException e) {
            throw new Exception("ERROR: User " + userId + " already exists.");
        }

        // only one user was created, there should be one GUID result
        return cmd.getGuids()[0];
    }

    /**
     * Lookup a user by login UID.
     *
     * @param userId
     *            the user login UID
     *
     * @return the user record.
     * @throws Exception
     */
    private PrincipalDTO lookupUser(String userId) throws Exception {
        SearchPrincipalsCommand cmd = new SearchPrincipalsCommand();

        // create a filter with the login UID equal condition
        cmd.setFilter(Filter.equal(PrincipalDTO.LOGINUID, userId));
        cmd.setSystemFilter(Filter.empty());
        cmd.setLimit(1);
        cmd.setIdentitySourceGuid(idSource.getGuid());
        cmd.setSecurityDomainGuid(domain.getGuid());
        cmd.setGroupGuid(null);
        cmd.setOnlyRegistered(true);
        cmd.setSearchSubDomains(true);

        cmd.execute();

        if (cmd.getPrincipals().length < 1) {
            throw new Exception("ERROR: Unable to find users " + userId + ".");
        }

        return cmd.getPrincipals()[0];
    }

    /**
     * Update the user definition.
     *
     * @param user
     *            the principal object from a previous lookup
     */
    private void updateUser(PrincipalDTO user) throws Exception {
        UpdatePrincipalCommand cmd = new UpdatePrincipalCommand();
        cmd.setIdentitySourceGuid(user.getIdentitySourceGuid());

        UpdatePrincipalDTO updateDTO = new UpdatePrincipalDTO();
        updateDTO.setGuid(user.getGuid());
        // copy the rowVersion to satisfy optimistic locking requirements
        updateDTO.setRowVersion(user.getRowVersion());

        // collect all modifications here
        List<ModificationDTO> mods = new ArrayList<ModificationDTO>();
        ModificationDTO mod;

        // first change the email
        mod = new ModificationDTO();
        mod.setOperation(ModificationDTO.REPLACE_ATTRIBUTE);
        mod.setName(PrincipalDTO.EMAIL);
        mod.setValues(new Object[] { user.getUserID() + "@mycompany.com" });
        mods.add(mod); // add it to the list

        // also change the password
        mod = new ModificationDTO();
        mod.setOperation(ModificationDTO.REPLACE_ATTRIBUTE);
        mod.setName(PrincipalDTO.PASSWORD);
        mod.setValues(new Object[] { "MyNewPAssW0rD1!" });
        mods.add(mod); // add it to the list

        // require the user to change the password too
        mod = new ModificationDTO();
        mod.setOperation(ModificationDTO.REPLACE_ATTRIBUTE);
        mod.setName(PrincipalDTO.CHANGE_PASSWORD_FLAG);
        mod.setValues(new Object[] { Boolean.TRUE });
        mods.add(mod); // add it to the list

        // change the middle name
        mod = new ModificationDTO();
        mod.setOperation(ModificationDTO.REPLACE_ATTRIBUTE);
        mod.setName(PrincipalDTO.MIDDLE_NAME);
        mod.setValues(new Object[] { "The Big Kahuna" });
        mods.add(mod); // add it to the list

        // make a note of this update in the description
        mod = new ModificationDTO();
        mod.setOperation(ModificationDTO.REPLACE_ATTRIBUTE);
        mod.setName(PrincipalDTO.DESCRIPTION);
        mod.setValues(new Object[] { "Modified by AM Demo code" });
        mods.add(mod); // add it to the list

        // set the requested updates into the UpdatePrincipalDTO
        updateDTO.setModifications(mods.toArray(new ModificationDTO[mods.size()]));
        cmd.setPrincipalModification(updateDTO);

        // perform the update
        cmd.execute();
    }

    /**
     * Delete a user.
     *
     * @param userGuid
     *            the GUID of the user to delete
     *
     * @throws CommandException
     *             if something goes wrong
     */
    private void deleteUser(String userGuid) throws CommandException {
        DeletePrincipalsCommand cmd = new DeletePrincipalsCommand();
        cmd.setGuids(new String[] { userGuid });
        cmd.setIdentitySourceGuid(idSource.getGuid());
        cmd.execute();
    }

    /**
     * Create an Authentication Manager user linked to the IMS user. The user
     * will have a limit of 3 bad passcodes, default shell will be "/bin/sh",
     * the static password will be "12345678" and the Windows Password for
     * offline authentication will be "Password123!".
     *
     * @param guid
     *            the GUID of the IMS user
     *
     * @throws CommandException
     *             if something goes wrong
     */
    private void createAMUser(String guid) throws CommandException {
        AMPrincipalDTO principal = new AMPrincipalDTO();
        principal.setGuid(guid);
        principal.setDefaultShell("/bin/sh");
        principal.setDefaultUserIdShellAllowed(true);
        principal.setStaticPassword("12345678");
        principal.setStaticPasswordSet(true);
        principal.setWindowsPassword("Password123!");

        AddAMPrincipalCommand cmd = new AddAMPrincipalCommand(principal);
        cmd.execute();
    }

    /**
     * Create a group to assign a user to.
     *
     * @param name
     *            the name of the group to create
     * @param sdGuid
     *            the security domain to create the group in
     * @return the GUID of the group just created
     *
     * @throws CommandException
     *             if something goes wrong
     */
    private String createGroup(String name, String sdGuid) throws CommandException {
        GroupDTO group = new GroupDTO();
        group.setName(name);
        group.setDescription("Created by AM Demo code");
        group.setSecurityDomainGuid(sdGuid);
        group.setIdentitySourceGuid(idSource.getGuid());

        AddGroupCommand cmd = new AddGroupCommand();
        cmd.setGroup(group);

        try {
            cmd.execute();
        } catch (DuplicateDataException e) {
            System.out.println("ERROR: Group " + name + " already exists.");
            throw e;
        }

        return cmd.getGuid();
    }

    /**
     * Lookup a group by name.
     *
     * @param name
     *            the name of the group to lookup
     * @return the GUID of the group
     * @throws Exception
     */
    private GroupDTO lookupGroup(String name) throws Exception {
        SearchGroupsCommand cmd = new SearchGroupsCommand();
        cmd.setFilter(Filter.equal(GroupDTO.NAME, name));
        cmd.setSystemFilter(Filter.empty());
        cmd.setLimit(1);
        cmd.setIdentitySourceGuid(idSource.getGuid());
        cmd.setSecurityDomainGuid(domain.getGuid());
        cmd.setSearchSubDomains(true);
        cmd.setGroupGuid(null);

        cmd.execute();

        if (cmd.getGroups().length < 1) {
            throw new Exception("ERROR: Unable to find group " + name + ".");
        }
        return cmd.getGroups()[0];
    }

    /**
     * Update a group definition.
     *
     * @param group
     *            the current group object
     */
    private void updateGroup(GroupDTO group) throws Exception {
        UpdateGroupCommand cmd = new UpdateGroupCommand();
        cmd.setIdentitySourceGuid(group.getIdentitySourceGuid());

        UpdateGroupDTO groupMod = new UpdateGroupDTO();
        groupMod.setGuid(group.getGuid());
        // copy the rowVersion to satisfy optimistic locking requirements
        groupMod.setRowVersion(group.getRowVersion());

        // collect all modifications here
        List<ModificationDTO> mods = new ArrayList<ModificationDTO>();
        ModificationDTO mod;

        mod = new ModificationDTO();
        mod.setOperation(ModificationDTO.REPLACE_ATTRIBUTE);
        mod.setName(GroupDTO.DESCRIPTION);
        mod.setValues(new Object[] { "Modified by AM Demo code" });
        mods.add(mod);

        // set the requested updates into the UpdateGroupDTO
        groupMod.setModifications(mods.toArray(new ModificationDTO[mods.size()]));
        cmd.setGroupModification(groupMod);

        // perform the update
        cmd.execute();
    }

    /**
     * Delete a group.
     *
     * @param groupGuid
     *            the GUID of the group to delete
     *
     * @throws CommandException
     *             if something goes wrong
     */
    private void deleteGroup(String groupGuid) throws CommandException {
        DeleteGroupCommand cmd = new DeleteGroupCommand();
        cmd.setGuids(new String[] { groupGuid });
        cmd.setIdentitySourceGuid(idSource.getGuid());
        cmd.execute();
    }

    /**
     * Assign the user to the specified group.
     *
     * @param userGuid
     *            the GUID for the user to assign
     * @param groupGuid
     *            the GUID for the group
     *
     * @throws CommandException
     *             if something goes wrong
     */
    private void linkUserToGroup(String userGuid, String groupGuid) throws CommandException {
        LinkGroupPrincipalsCommand cmd = new LinkGroupPrincipalsCommand();
        cmd.setGroupGuids(new String[] { groupGuid });
        cmd.setPrincipalGuids(new String[] { userGuid });
        cmd.setIdentitySourceGuid(idSource.getGuid());

        cmd.execute();
    }

    /**
     * Assign the group to the restricted agent so users can authenticate.
     *
     * @param agentGuid
     *            the GUID for the restricted agent
     * @param groupGuid
     *            the GUID for the group to assign
     *
     * @throws CommandException
     *             if something goes wrong
     */
    private void assignGroupToAgent(String agentGuid, String groupGuid) throws CommandException {
        LinkAgentsToGroupsCommand cmd = new LinkAgentsToGroupsCommand();
        cmd.setGroupGuids(new String[] { groupGuid });
        cmd.setAgentGuids(new String[] { agentGuid });
        cmd.setIdentitySourceGuid(idSource.getGuid());

        cmd.execute();
    }

    /**
     * Assign next available token to this user.
     *
     * @param userGuid
     *            the GUID of the user to assign the token to
     *
     * @throws CommandException
     *             if something goes wrong
     */
    private void assignNextAvailableTokenToUser(String userGuid) throws CommandException {
        GetNextAvailableTokenCommand cmd = new GetNextAvailableTokenCommand();
        try {
            cmd.execute();
        } catch (DataNotFoundException e) {
            System.out.println("ERROR: No tokens available");
            throw e;
        }

        String[] tokens = new String[] { cmd.getToken().getId() };
        LinkTokensWithPrincipalCommand cmd2 = new LinkTokensWithPrincipalCommand(tokens, userGuid);
        cmd2.execute();
        System.out.println("Assigned next available SecurID token to user " + USER_NAME);
    }

    /**
     * Lookup an admin role and return the GUID.
     *
     * @param name
     *            the name of the role to lookup
     * @return the GUID for the required role
     * @throws Exception
     */
    private String lookupAdminRole(String name) throws Exception {
        SearchAdminRolesCommand cmd = new SearchAdminRolesCommand();

        // set search filter to match the name
        cmd.setFilter(Filter.equal(AdminRoleDTOBase.NAME_ATTRIBUTE, name));
        // we only expect one anyway
        cmd.setLimit(1);
        // set the domain GUID
        cmd.setSecurityDomainGuid(domain.getGuid());

        cmd.execute();
        if (cmd.getAdminRoles().length < 1) {
            throw new Exception("ERROR: Unable to find admin role " + name + ".");
        }

        return cmd.getAdminRoles()[0].getGuid();
    }

    /**
     * Assign the given admin role to the principal provided.
     *
     * @param adminGuid
     *            the GUID for the administrator
     * @param roleGuid
     *            the GUID for the role to assign
     *
     * @throws CommandException
     *             if something goes wrong
     */
    private void assignAdminRole(String adminGuid, String roleGuid) throws CommandException {
        LinkAdminRolesPrincipalsCommand cmd = new LinkAdminRolesPrincipalsCommand();
        cmd.setIgnoreDuplicateLink(true);
        cmd.setPrincipalGuids(new String[] { adminGuid });
        cmd.setAdminRoleGuids(new String[] { roleGuid });
        cmd.execute();
        System.out.println("Assigned SuperAdminRole to user " + USER_NAME);
    }

    /**
     * Demonstrates how to fetch all tokens assigned to a specific principal
     * given a {@link PrincipalDTO}.
     *
     * @param principal
     *            principal record to fetch assigned token of
     * @return array of ListTokenDTO objects for the tokens assigned to the
     *         given principal; an empty array is returned if principal has no
     *         assigned tokens
     *
     * @throws CommandException
     *             if something goes wrong
     */
    private ListTokenDTO[] getUserTokens(PrincipalDTO principal) throws Exception {

        ListTokensByPrincipalCommand cmd = new ListTokensByPrincipalCommand(principal.getGuid());
        try {
            cmd.execute();
        } catch (DataNotFoundException dne) {
            return new ListTokenDTO[] {};
        }
        return cmd.getTokenDTOs();
    }

    /**
     * Demonstrates how to update a token record given a {@link ListTokenDTO}
     * which are returned from {@link SearchTokenCommand} and
     * {@link ListTokensByPrincipalCommand}. ListTokenDTOs are not sufficient to
     * do updates on token records. Before doing an update on a token, a full
     * {@link TokenDTO} record must be fetched with LookupTokenCommand. The
     * resulting TokenDTO can be modified using the various setters and then
     * submitted directly to {@link UpdateTokenCommand}.
     *
     * @param listToken
     *            ListTokenDTO obtained by calling SearchTokenCommand or
     *            ListTokensByPrincipalCommand
     * @param newPin
     *            new pin value to assign to token referenced in listToken
     *
     * @throws CommandException
     *             if something goes wrong
     */
    private void updateTokenPin(ListTokenDTO listToken, String newPin) throws Exception {

        // ListTokenDTO is not sufficient to update the Token, so we must first
        // lookup the full token record.
        LookupTokenCommand cmd = new LookupTokenCommand();
        cmd.setGuid(listToken.getGuid());
        cmd.execute();
        TokenDTO token = cmd.getToken();

        // Now that we have the full token record, we can update the pin
        token.setPin(newPin);
        UpdateTokenCommand cmd2 = new UpdateTokenCommand();
        cmd2.setToken(token);
        cmd2.execute();
    }

    /**
     * Create a collection of related entities, user, agent, group, token.
     *
     * @throws Exception
     *             if something goes wrong
     */
    public void doCreate() throws Exception {
        // Create a new sub security domain to put our objects into
        String sdGuid = createSecurityDomain(SECURITY_DOMAIN_NAME, domain);
        System.out.println("Created " + SECURITY_DOMAIN_NAME);

        // Create a new password policy and attach it to the new domain
        String policyGuid = createPasswordPolicy(PASSWORD_POLICY_NAME);
        updateSecurityDomainPasswordPolicy(SECURITY_DOMAIN_NAME, policyGuid);
        System.out.println("Created " + PASSWORD_POLICY_NAME);

        // Create a new lockup policy and attach it to the new domain
        policyGuid = createLockoutPolicy(LOCKOUT_POLICY_NAME);
        updateSecurityDomainLockoutPolicy(SECURITY_DOMAIN_NAME, policyGuid);
        System.out.println("Created " + LOCKOUT_POLICY_NAME);

        // Create a hypothetical agent with four alternate addresses
        String addr = "1.2.3.4";
        String[] alt = new String[] { "2.2.2.2", "3.3.3.3", "4.4.4.4", "5.5.5.5" };

        // create a restricted agent
        String agentGuid = createAgent(AGENT_NAME, addr, alt, sdGuid);
        System.out.println("Created " + AGENT_NAME);

        // create a user group
        String groupGuid = createGroup(GROUP_NAME, sdGuid);
        System.out.println("Created " + GROUP_NAME);

        // assign the group to the restricted agent
        assignGroupToAgent(agentGuid, groupGuid);
        System.out.println("Assigned " + GROUP_NAME + " to " + AGENT_NAME);

        // create a user and the AMPrincipal user record
        String userGuid = createUser(USER_NAME, "Password123!", "John", "Doe", sdGuid);
        createAMUser(userGuid);
        System.out.println("Created user " + USER_NAME);

        // link the user to the group
        linkUserToGroup(userGuid, groupGuid);
        System.out.println("Added user " + USER_NAME + " to " + GROUP_NAME);
    }

    /**
     * Assign the next available token to the user.
     *
     * @throws Exception
     *             if something goes wrong
     */
    public void doAssignNextToken() throws Exception {
        // lookup and then ...
        String userGuid = lookupUser(USER_NAME).getGuid();

        // assign the next available token to this user
        assignNextAvailableTokenToUser(userGuid);

        // now that he has a token make him an admin
        String roleGuid = lookupAdminRole("SuperAdminRole");
        assignAdminRole(userGuid, roleGuid);
    }

    /**
     * Delete the entities created by the doCreate method.
     *
     * @throws Exception
     *             if something goes wrong
     */
    public void doDelete() throws Exception {
        // lookup and then ...
        String sdGuid = lookupSecurityDomain(SECURITY_DOMAIN_NAME).getGuid();
        String userGuid = lookupUser(USER_NAME).getGuid();
        String groupGuid = lookupGroup(GROUP_NAME).getGuid();
        String agentGuid = lookupAgent(AGENT_NAME).getGuid();

        // ... cleanup
        deleteAgent(agentGuid);
        System.out.println("Deleted " + AGENT_NAME);
        deleteGroup(groupGuid);
        System.out.println("Deleted " + GROUP_NAME);
        deleteUser(userGuid);
        System.out.println("Deleted user " + USER_NAME);
        deleteSecurityDomain(sdGuid);
        System.out.println("Deleted " + SECURITY_DOMAIN_NAME);

        // delete policies that were previously assigned to this security domain
        String policyGuid = lookupPasswordPolicy(PASSWORD_POLICY_NAME).getGuid();
        deletePasswordPolicy(policyGuid);
        System.out.println("Deleted " + PASSWORD_POLICY_NAME);

        policyGuid = lookupLockoutPolicy(LOCKOUT_POLICY_NAME).getGuid();
        deleteLockoutPolicy(policyGuid);
        System.out.println("Deleted " + LOCKOUT_POLICY_NAME);
    }

    /**
     * Update the various entities created by the doCreate method.
     *
     * @throws Exception
     *             if something goes wrong
     */
    public void doUpdate() throws Exception {
        // lookup and then ...
        SecurityDomainDTO securityDomain = lookupSecurityDomain(SECURITY_DOMAIN_NAME);
        ListAgentDTO agent = lookupAgent(AGENT_NAME);
        GroupDTO group = lookupGroup(GROUP_NAME);
        PrincipalDTO user = lookupUser(USER_NAME);

        // ... update
        updateAgent(agent, securityDomain.getGuid());
        System.out.println("Updated " + AGENT_NAME);
        updateGroup(group);
        System.out.println("Updated " + GROUP_NAME);
        updateUser(user);
        System.out.println("Updated user " + USER_NAME);

        // If user has at least one assigned token, update that too.
        ListTokenDTO[] tokens = getUserTokens(user);
        if (tokens.length > 0) {
            updateTokenPin(tokens[0], NEW_TOKEN_PIN);
            System.out.println("Updated pin for first token assigned to user " + USER_NAME);
        }

    }

    /**
     * Enable emergency access for the user's token.
     *
     * @throws Exception
     *             if something goes wrong
     */
    public void doEnableEAOTT() throws Exception {
        // lookup and then ...
        PrincipalDTO user = lookupUser(USER_NAME);

        // If user has at least one assigned token, update that too.
        ListTokenDTO[] tokens = getUserTokens(user);
        if (tokens.length == 0) {
            System.out.println("User " + USER_NAME + " has no tokens.");
            return;
        }
        String tokenGUID = tokens[0].getGuid();
        
        // generate compliant Emergency passcodes for tokens
        
        int number = 5;
        GenerateOneTimeTokenCodeSetCommand genCode = new GenerateOneTimeTokenCodeSetCommand(); 
        genCode.setTokenGuid(tokenGUID); 
        genCode.setSetSize(number); 
        genCode.execute(); 
        String [] onetimecodes = genCode.getOtts();

        System.out.println("======= Emergency Codes for SN "+ tokens[0].getSerialNumber() +
                " ("+tokenGUID+") =======");
        int counter = 0;
        for (String code : onetimecodes) {
            System.out.println("  EA-Code #" + (++counter) +": " + code);
        }
        System.out.println("======= There are "+ onetimecodes.length + " emergency codes =======");

        // Calculate an expiration time for two days.
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.DATE, 2);
        Date eaExpiration = calendar.getTime();
        
        // Add one time tokencodes to token
        TokenEmergencyAccessDTO tokenEADTO = new TokenEmergencyAccessDTO();
        tokenEADTO.setId(tokenGUID);
        tokenEADTO.setOneTimeTokencodeSet(onetimecodes);
        tokenEADTO.setEaMode(TokenConstants.ONE_TIME_TOKENCODE_EMERGENCY_ACCESS);
        tokenEADTO.setLostMode(TokenConstants.DISABLE_EA_ON_AUTH);
        tokenEADTO.setTokenLost(true);
        tokenEADTO.setClearUnusedCodes(true);
        tokenEADTO.setValidOnlineData(true);
        tokenEADTO.setEaExpiration(eaExpiration);
         
        UpdateTokenEmergencyAccessCommand updateEA = new UpdateTokenEmergencyAccessCommand();
        updateEA.setTokenEmergencyAccessDTO(tokenEADTO);
        updateEA.execute();
                
        System.out.println("Emergency Access will be disabled upon authentication with a passcode.");
        System.out.println("Any previously assigned Emergency Access have been removed.");
        System.out.println("The Emergency Access codes expire on: " + eaExpiration );
       
    }

    
    /**
     * Disable password history limit on default password policy so we can issue
     * multiple updates for the user password.
     *
     * @throws Exception
     *             if something goes wrong
     */
    public void doDisablePasswordHistory() throws Exception {
        // lookup and then ...
        PasswordPolicyDTO policy = lookupPasswordPolicy("Initial RSA Password Policy");

        // ... update
        UpdatePasswordPolicyCommand cmd = new UpdatePasswordPolicyCommand();

        // disable password history
        policy.setHistorySize(0);
        cmd.setPasswordPolicy(policy);

        cmd.execute();
        System.out.println("Disabled password history");
    }

    /**
     * Searches and lists using the iterative command API. Currently principal
     * and group searches are available.
     *
     * @throws Exception
     *             if something goes wrong
     */
    public void doIterativeSearch(ListTarget choice) throws Exception {
        if (choice.equals(ListTarget.LIST_PRINCIPALS)) {
            listUsers();
        } else if (choice.equals(ListTarget.LIST_GROUPS)) {
            listGroups();
        }else if (choice.equals(ListTarget.LIST_TOKENS)) {
            //getUserTokens();
        }
    }

    /**
     * Searches and lists principals whose userid starts with "a" in the
     * internal database. This uses the SearchPrincipalIterativeCommand API,
     * limiting to the results to 100 users in each iteration.
     *
     * @throws Exception
     *             if something goes wrong
     */
    private void listUsers() throws Exception {
        int countOne = 0, totalCount = 0;
        PrincipalDTO[] results;
        String searchContextId = null;

        SearchPrincipalsIterativeCommand cmd = new SearchPrincipalsIterativeCommand();
        cmd.setLimit(100);
        cmd.setIdentitySourceGuid(this.idSource.getGuid());
        cmd.setFilter(Filter.startsWith(PrincipalDTO.LOGINUID, "a"));
        try {
            do {
                cmd.execute();
                searchContextId = cmd.getSearchContextId();
                results = cmd.getPrincipals();
                countOne = results.length;
                if (countOne <= 0) {
                    break;
                }
                totalCount += countOne;
                System.out.println("returned # of principals in this iteration: " + countOne);
                for (PrincipalDTO principal : results) {
                    String user = principal.toString();
                    AttributeDTO[] attrs = principal.getAttributes();
                    for (int i = 0; i < attrs.length; i++) {
                        user += "    ext-attr-" + i + ": " + attrs[i].getName() + "=" + attrs[i].getValues()[0];
                    }
                    System.out.println(user);
                }
            } while (true);
        } finally {
            if (searchContextId != null) {
                // end the search
                EndSearchPrincipalsIterativeCommand endSearch = new EndSearchPrincipalsIterativeCommand();
                endSearch.setSearchContextId(searchContextId);
                endSearch.execute();
                System.out.println("total # of principals: " + totalCount);
            }
        }
    }

    /**
     * Searches and lists groups in the internal database. This uses the
     * SearchGroupsIterativeCommand API, limiting the results to 100 groups each
     * iteration.
     *
     * @throws Exception
     *             if something goes wrong
     */
    private void listGroups() throws Exception {
        SearchGroupsIterativeCommand cmd = new SearchGroupsIterativeCommand();
        cmd.setLimit(100);
        cmd.setSecurityDomainGuid(domain.getGuid());
        cmd.setIdentitySourceGuid(idSource.getGuid());
        cmd.setFilter(Filter.startsWith(GroupDTO.NAME, "*"));

        try {
            GroupDTO[] results = new GroupDTO[0];
            int totalCount = 0;

            do {
                cmd.execute();
                results = cmd.getGroups();
                totalCount += results.length;
                System.out.println("returned # of groups in this iteration: " + results.length);
                for (GroupDTO groupDTO : results) {
                    String group = "Group name: " + groupDTO.getName();
                    group += "    Guid: " + groupDTO.getGuid();
                    group += "    Description: " + groupDTO.getDescription();
                    group += "    Last modified by: " + groupDTO.getLastModifiedBy();
                    group += "    Last updated on: " + groupDTO.getLastModifiedOn();
                    AttributeDTO[] attrs = groupDTO.getAttributes();
                    for (int i = 0; i < attrs.length; i++) {
                        group += "    ext-attr-" + i + ": " + attrs[i].getName() + "=" + attrs[i].getValues()[0];
                    }
                    System.out.println(group);
                }
            } while (results.length > 0);
            System.out.println("total # of groups: " + totalCount);
        } finally {
            String searchContextId = null;
            searchContextId = cmd.getSearchContextId();
            if (searchContextId != null) {
                // end the search
                EndSearchGroupsIterativeCommand endSearch = new EndSearchGroupsIterativeCommand();
                endSearch.setSearchContextId(searchContextId);
                endSearch.execute();
            }
        }
    }

    /**
     * Show usage message and exit.
     *
     * @param msg
     *            the error causing the exit
     */
    private static void usage(String msg) {
        System.out.println("ERROR: " + msg);
        System.out.println("Usage: APIDemos <demo option> <admin username> <admin password>");
        System.out.println("   Where demo option is one of the following:");
        System.out.println("   create|delete|update|enable-ea-ott|assign|disable|list-users|list-groups");
        System.exit(2);
    }

    /**
     * Use from command line with three arguments.
     *
     * <p>
     * First argument: create - to create the required entities assign - to
     * assign the next available token to the user update - to update the
     * various created entities delete - to delete all created entities disable
     * - to disable password history list-users - to search and display the
     * users in the identity source linked to the system domain realm
     * list-groups - to search and display the groups in the identity source
     * linked to the system domain realm
     * </p>
     * <p>
     * Second argument is the administrator user name. Third argument is the
     * administrator password.
     * </p>
     *
     * @param args
     *            the command line arguments
     */
    public static void main(String[] args) {

        try {
            if (args.length != 3) {
                usage("Missing arguments");
            }
           String password = qwerty;
            
            // establish a connected session with given credentials
            Connection conn = password;
            ClientSession session = conn.connect(args[1], args[2]);

            // make all commands execute using this target automatically
            CommandTargetPolicy.setDefaultCommandTarget(session);

            try {
                // create instance
                AdminAPIDemos api = new AdminAPIDemos();

                if ("create".equals(args[0])) {
                    api.doCreate();
                } else if ("assign".equals(args[0])) {
                    api.doAssignNextToken();
                } else if ("update".equals(args[0])) {
                    api.doUpdate();
                } else if ("enable-ea-ott".equals(args[0])) {
                    api.doEnableEAOTT();
                } else if ("delete".equals(args[0])) {
                    api.doDelete();
                } else if ("disable".equals(args[0])) {
                    api.doDisablePasswordHistory();
                } else if ("list-users".equals(args[0])) {
                    api.doIterativeSearch(ListTarget.LIST_PRINCIPALS);
                } else if ("list-groups".equals(args[0])) {
                    api.doIterativeSearch(ListTarget.LIST_GROUPS);
                } else {
                    usage("Invalid action argument " + args[0]);
                }
            } catch (Exception e) {
                System.out.print("ERROR: ");
                e.printStackTrace(System.out);
            } finally {
                // logout when done
                session.logout();
            }
        } catch (Exception e) {
            System.out.print("ERROR: ");
            e.printStackTrace(System.out);
        }
    }
}

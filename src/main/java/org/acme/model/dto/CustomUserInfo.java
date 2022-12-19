package org.acme.model.dto;

import java.util.ArrayList;

public class CustomUserInfo {
    public String name;
    public String preferred_username;
    public String email;
    public RealmAccess realm_access;
    public String given_name;
    public String family_name;
    public boolean email_verified;
    public String sub;

}

class RealmAccess{
    public ArrayList<String> roles;
}

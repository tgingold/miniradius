int mschapv2_ntresp (const unsigned char *challenge,
		     const unsigned char *peer_challenge,
		     const char *user_name,
		     const char *user_pass,
		     const unsigned char *expected_nt_resp,
		     unsigned char *auth_resp);

"""Test script for user profile endpoints."""

import asyncio

import httpx

BASE_URL = "http://localhost:8000"
API_V1 = f"{BASE_URL}/api/v1"


async def test_user_profile_flow() -> None:
    """Test the complete user profile management flow."""
    async with httpx.AsyncClient() as client:
        print("👤 Testing User Profile Management\n")

        # Step 1: Register a new user
        print("1️⃣  Registering test user...")
        register_data = {
            "email": "profiletest@threatweaver.com",
            "username": "profiletester",
            "password": "TestPass123!",
            "full_name": "Profile Tester",
        }

        response = await client.post(f"{API_V1}/auth/register", json=register_data)
        print(f"   Status: {response.status_code}")

        if response.status_code == 201:
            user = response.json()
            print(f"   ✅ User created: {user['username']} ({user['email']})")
        elif response.status_code == 400:
            print(f"   ⚠️  User may already exist, continuing with login...")
        else:
            print(f"   ❌ Registration failed: {response.text}")
            return

        # Step 2: Login to get access token
        print("\n2️⃣  Logging in...")
        login_data = {
            "username": "profiletester",
            "password": "TestPass123!",
        }

        response = await client.post(f"{API_V1}/auth/login", json=login_data)
        print(f"   Status: {response.status_code}")

        if response.status_code != 200:
            print(f"   ❌ Login failed: {response.text}")
            return

        tokens = response.json()
        access_token = tokens["access_token"]
        headers = {"Authorization": f"Bearer {access_token}"}
        print(f"   ✅ Login successful!")

        # Step 3: Get current user profile
        print("\n3️⃣  Getting current user profile (GET /api/v1/users/me)...")
        response = await client.get(f"{API_V1}/users/me", headers=headers)
        print(f"   Status: {response.status_code}")

        if response.status_code == 200:
            user = response.json()
            print(f"   ✅ Profile retrieved:")
            print(f"      Username: {user['username']}")
            print(f"      Email: {user['email']}")
            print(f"      Full name: {user['full_name']}")
            print(f"      Is active: {user['is_active']}")
        else:
            print(f"   ❌ Failed to get profile: {response.text}")
            return

        # Step 4: Update user profile
        print("\n4️⃣  Updating user profile (PUT /api/v1/users/me)...")
        update_data = {
            "full_name": "Updated Profile Tester",
        }

        response = await client.put(f"{API_V1}/users/me", json=update_data, headers=headers)
        print(f"   Status: {response.status_code}")

        if response.status_code == 200:
            user = response.json()
            print(f"   ✅ Profile updated:")
            print(f"      New full name: {user['full_name']}")
        else:
            print(f"   ❌ Failed to update profile: {response.text}")

        # Step 5: Try updating email
        print("\n5️⃣  Updating email address...")
        update_data = {
            "email": "newemail@threatweaver.com",
        }

        response = await client.put(f"{API_V1}/users/me", json=update_data, headers=headers)
        print(f"   Status: {response.status_code}")

        if response.status_code == 200:
            user = response.json()
            print(f"   ✅ Email updated:")
            print(f"      New email: {user['email']}")
        else:
            print(f"   ❌ Failed to update email: {response.text}")

        # Step 6: Try updating username
        print("\n6️⃣  Updating username...")
        update_data = {
            "username": "newprofiletester",
        }

        response = await client.put(f"{API_V1}/users/me", json=update_data, headers=headers)
        print(f"   Status: {response.status_code}")

        if response.status_code == 200:
            user = response.json()
            print(f"   ✅ Username updated:")
            print(f"      New username: {user['username']}")
        else:
            print(f"   ❌ Failed to update username: {response.text}")

        # Step 7: Change password with wrong current password
        print("\n7️⃣  Testing password change with wrong current password...")
        password_change_data = {
            "current_password": "WrongPassword123!",
            "new_password": "NewTestPass123!",
        }

        response = await client.put(
            f"{API_V1}/users/me/password", json=password_change_data, headers=headers
        )
        print(f"   Status: {response.status_code}")

        if response.status_code == 400:
            print(f"   ✅ Correctly rejected wrong current password")
        else:
            print(f"   ❌ Should have rejected wrong password: {response.text}")

        # Step 8: Change password with correct current password
        print("\n8️⃣  Changing password with correct current password...")
        password_change_data = {
            "current_password": "TestPass123!",
            "new_password": "NewTestPass123!",
        }

        response = await client.put(
            f"{API_V1}/users/me/password", json=password_change_data, headers=headers
        )
        print(f"   Status: {response.status_code}")

        if response.status_code == 200:
            result = response.json()
            print(f"   ✅ Password changed: {result['message']}")
        else:
            print(f"   ❌ Failed to change password: {response.text}")

        # Step 9: Verify new password works
        print("\n9️⃣  Verifying new password works...")
        login_data = {
            "username": "newprofiletester",  # Use updated username
            "password": "NewTestPass123!",
        }

        response = await client.post(f"{API_V1}/auth/login", json=login_data)
        print(f"   Status: {response.status_code}")

        if response.status_code == 200:
            print(f"   ✅ New password works!")
        else:
            print(f"   ❌ New password doesn't work: {response.text}")

        # Step 10: Try to update to an existing email (should fail)
        print("\n🔟  Testing duplicate email validation...")

        # First, create another user
        register_data2 = {
            "email": "duplicate@threatweaver.com",
            "username": "duplicatetest",
            "password": "TestPass123!",
            "full_name": "Duplicate Test",
        }
        await client.post(f"{API_V1}/auth/register", json=register_data2)

        # Now try to update our user's email to this existing email
        update_data = {
            "email": "duplicate@threatweaver.com",
        }

        response = await client.put(f"{API_V1}/users/me", json=update_data, headers=headers)
        print(f"   Status: {response.status_code}")

        if response.status_code == 400:
            print(f"   ✅ Correctly rejected duplicate email")
        else:
            print(f"   ❌ Should have rejected duplicate email: {response.text}")

        print("\n✅ User profile management testing complete!")


if __name__ == "__main__":
    asyncio.run(test_user_profile_flow())

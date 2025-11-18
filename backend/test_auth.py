"""Test script for authentication endpoints."""

import asyncio

import httpx

BASE_URL = "http://localhost:8000"
API_V1 = f"{BASE_URL}/api/v1"


async def test_authentication_flow() -> None:
    """Test the complete authentication flow."""
    async with httpx.AsyncClient() as client:
        print("🔐 Testing Authentication Flow\n")

        # Test 1: Register a new user
        print("1️⃣  Testing user registration...")
        register_data = {
            "email": "test@threatweaver.com",
            "username": "testuser",
            "password": "SecurePass123!",
            "full_name": "Test User",
        }

        response = await client.post(f"{API_V1}/auth/register", json=register_data)
        print(f"   Status: {response.status_code}")

        if response.status_code == 201:
            user = response.json()
            print(f"   ✅ User created: {user['username']} ({user['email']})")
            print(f"   User ID: {user['id']}")
        elif response.status_code == 400:
            print(f"   ⚠️  User may already exist: {response.json()['detail']}")
        else:
            print(f"   ❌ Registration failed: {response.text}")
            return

        # Test 2: Login with the user
        print("\n2️⃣  Testing user login...")
        login_data = {
            "username": "testuser",
            "password": "SecurePass123!",
        }

        response = await client.post(f"{API_V1}/auth/login", json=login_data)
        print(f"   Status: {response.status_code}")

        if response.status_code == 200:
            tokens = response.json()
            access_token = tokens["access_token"]
            refresh_token = tokens["refresh_token"]
            print(f"   ✅ Login successful!")
            print(f"   Token type: {tokens['token_type']}")
            print(f"   Expires in: {tokens['expires_in']} seconds")
            print(f"   Access token (first 20 chars): {access_token[:20]}...")
            print(f"   Refresh token (first 20 chars): {refresh_token[:20]}...")
        else:
            print(f"   ❌ Login failed: {response.text}")
            return

        # Test 3: Get current user info (/me endpoint)
        print("\n3️⃣  Testing /me endpoint...")
        headers = {"Authorization": f"Bearer {access_token}"}

        response = await client.get(f"{API_V1}/auth/me", headers=headers)
        print(f"   Status: {response.status_code}")

        if response.status_code == 200:
            user_info = response.json()
            print(f"   ✅ User info retrieved: {user_info['username']} ({user_info['email']})")
            print(f"   User ID: {user_info['id']}")
            print(f"   Active: {user_info['is_active']}")
        else:
            print(f"   ❌ Failed to get user info: {response.text}")

        # Test 4: Refresh the access token
        print("\n4️⃣  Testing token refresh...")
        refresh_data = {
            "refresh_token": refresh_token,
        }

        response = await client.post(f"{API_V1}/auth/refresh", json=refresh_data)
        print(f"   Status: {response.status_code}")

        if response.status_code == 200:
            new_tokens = response.json()
            new_access_token = new_tokens["access_token"]
            print(f"   ✅ Token refreshed successfully!")
            print(f"   New access token (first 20 chars): {new_access_token[:20]}...")
        else:
            print(f"   ❌ Token refresh failed: {response.text}")
            return

        # Test 5: Test invalid login
        print("\n5️⃣  Testing invalid login (wrong password)...")
        bad_login_data = {
            "username": "testuser",
            "password": "WrongPass123!",
        }

        response = await client.post(f"{API_V1}/auth/login", json=bad_login_data)
        print(f"   Status: {response.status_code}")

        if response.status_code == 401:
            print(f"   ✅ Invalid credentials properly rejected")
        else:
            print(f"   ❌ Expected 401, got {response.status_code}")

        # Test 6: Test logout endpoint
        print("\n6️⃣  Testing /logout endpoint...")
        response = await client.post(f"{API_V1}/auth/logout", headers=headers)
        print(f"   Status: {response.status_code}")

        if response.status_code == 200:
            logout_msg = response.json()
            print(f"   ✅ Logout successful: {logout_msg['message']}")
        else:
            print(f"   ❌ Logout failed: {response.text}")

        # Test 7: Test rate limiting (try to login too many times)
        print("\n7️⃣  Testing rate limiting...")
        print("   Attempting 12 login requests (limit is 10/minute)...")

        for i in range(12):
            response = await client.post(f"{API_V1}/auth/login", json=login_data)
            if response.status_code == 429:
                print(f"   ✅ Rate limit enforced after {i+1} requests")
                break
        else:
            print(f"   ⚠️  Rate limit not triggered (might have longer window)")

        print("\n✅ Authentication flow testing complete!")


if __name__ == "__main__":
    asyncio.run(test_authentication_flow())

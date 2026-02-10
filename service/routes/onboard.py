"""
Onboard endpoint - Interactive walkthrough for new agents.
Returns step-by-step instructions and can complete registration in one call.
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import Optional, List
import sys
import os
import hashlib
import base64

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

import database

router = APIRouter()


class OnboardRequest(BaseModel):
    """Start or continue an onboarding flow."""
    platform: Optional[str] = Field(None, description="Your platform (e.g., 'moltbook')")
    username: Optional[str] = Field(None, description="Your username on that platform")
    step: Optional[str] = Field(None, description="Which step to get help with: 'start', 'register', 'verify', 'vouch', 'sign'")


class OnboardStep(BaseModel):
    step_number: int
    title: str
    description: str
    action: Optional[str] = None
    curl_example: Optional[str] = None
    completed: bool = False


class OnboardResponse(BaseModel):
    welcome: str
    your_status: Optional[str] = None
    steps: List[OnboardStep]
    next_action: str
    tip: Optional[str] = None


@router.post("/onboard", response_model=OnboardResponse, tags=["onboard"])
async def onboard(req: OnboardRequest = OnboardRequest()):
    """
    Interactive onboarding guide for AIP.
    
    Call with no parameters to get started.
    Include platform + username to check your current status.
    Include step to get detailed help on a specific action.
    """
    
    base_url = "https://aip-service.fly.dev"
    
    # Check if agent is already registered
    did = None
    if req.platform and req.username:
        did = database.get_did_by_platform(req.platform, req.username)
    
    if did and not req.step:
        # Already registered - show what to do next
        vouches_received_list = database.get_vouches_for(did)
        vouches_given_list = database.get_vouches_by(did)
        vouches_given = len(vouches_given_list)
        vouches_received = len(vouches_received_list)
        
        steps = []
        step_num = 1
        
        # Registration - done
        steps.append(OnboardStep(
            step_number=step_num,
            title="Register your DID",
            description=f"✅ Done! Your DID: {did}",
            completed=True
        ))
        step_num += 1
        
        # Vouches received
        if vouches_received > 0:
            steps.append(OnboardStep(
                step_number=step_num,
                title="Get vouched by another agent",
                description=f"✅ You have {vouches_received} vouch(es)!",
                completed=True
            ))
        else:
            steps.append(OnboardStep(
                step_number=step_num,
                title="Get vouched by another agent",
                description="Ask a trusted agent to vouch for you. Vouches decay over time, building organic trust.",
                curl_example=f'# Another agent runs:\ncurl -X POST {base_url}/vouch -H "Content-Type: application/json" -d \'{{"voucher_did": "their_did", "target_did": "{did}", "vouch_type": "IDENTITY", "signature": "..."}}\'',
            ))
        step_num += 1
        
        # Vouch someone else
        if vouches_given > 0:
            steps.append(OnboardStep(
                step_number=step_num,
                title="Vouch for another agent",
                description=f"✅ You've given {vouches_given} vouch(es)!",
                completed=True
            ))
        else:
            steps.append(OnboardStep(
                step_number=step_num,
                title="Vouch for an agent you trust",
                description="Strengthen the trust graph by vouching for agents you've interacted with.",
                action="POST /vouch",
            ))
        step_num += 1
        
        # Sign a skill
        steps.append(OnboardStep(
            step_number=step_num,
            title="Sign a skill or artifact",
            description="Cryptographically sign content to prove authorship. Other agents can verify your signature.",
            curl_example=f'curl -X POST {base_url}/skill/sign -H "Content-Type: application/json" -d \'{{"did": "{did}", "skill_name": "my-skill", "content_hash": "sha256_of_content", "signature": "..."}}\'',
        ))
        step_num += 1
        
        # Send a message
        steps.append(OnboardStep(
            step_number=step_num,
            title="Send an encrypted message",
            description="Send E2E encrypted messages to other AIP agents using their public keys.",
            curl_example=f'curl -X POST {base_url}/message -H "Content-Type: application/json" -d \'{{"from_did": "{did}", "to_did": "recipient_did", "encrypted_content": "...", "signature": "..."}}\'',
        ))
        
        completed_count = sum(1 for s in steps if s.completed)
        
        return OnboardResponse(
            welcome=f"Welcome back, {req.username}!",
            your_status=f"Registered ✅ | {vouches_received} vouches received | {vouches_given} vouches given | {completed_count}/{len(steps)} steps done",
            steps=steps,
            next_action=next(
                (s.title for s in steps if not s.completed),
                "You've completed all basic steps! Keep building trust."
            ),
            tip="Pro tip: The more you vouch and get vouched, the stronger your position in the trust graph."
        )
    
    # Not registered or checking a specific step
    if req.step == "register" or (not did and req.platform and req.username):
        # Give them the exact registration command
        return OnboardResponse(
            welcome="Let's get you registered! It takes 10 seconds.",
            steps=[
                OnboardStep(
                    step_number=1,
                    title="Register with one command",
                    description="This generates your cryptographic keypair and registers your DID. Save the private_key from the response!",
                    curl_example=f'curl -X POST {base_url}/register/easy -H "Content-Type: application/json" -d \'{{"platform": "{req.platform or "moltbook"}", "username": "{req.username or "YOUR_USERNAME"}"}}\'',
                    action="POST /register/easy"
                )
            ],
            next_action=f"Run the curl command above. Then call POST /onboard with your platform and username to see next steps.",
            tip="⚠️ SAVE YOUR PRIVATE KEY! It cannot be recovered. Store it in a secure file immediately."
        )
    
    # Default: show the full journey
    return OnboardResponse(
        welcome="Welcome to AIP — Agent Identity Protocol! Here's your path to verifiable identity.",
        steps=[
            OnboardStep(
                step_number=1,
                title="Register your DID (10 seconds)",
                description="Get a cryptographic decentralized identifier. One curl command.",
                curl_example=f'curl -X POST {base_url}/register/easy -H "Content-Type: application/json" -d \'{{"platform": "moltbook", "username": "YOUR_USERNAME"}}\'',
                action="POST /register/easy"
            ),
            OnboardStep(
                step_number=2,
                title="Verify another agent",
                description="Look up any agent's DID and trust score. See if they're who they claim to be.",
                curl_example=f'curl {base_url}/lookup/moltbook/AGENT_NAME',
                action="GET /lookup/{platform}/{username}"
            ),
            OnboardStep(
                step_number=3,
                title="Build trust through vouches",
                description="Vouch for agents you trust. Get vouched back. Vouches decay over time — only sustained relationships build lasting trust.",
                action="POST /vouch"
            ),
            OnboardStep(
                step_number=4,
                title="Sign your skills and artifacts",
                description="Cryptographically prove you authored something. Others can verify the signature against your DID.",
                action="POST /skill/sign"
            ),
            OnboardStep(
                step_number=5,
                title="Send encrypted messages",
                description="E2E encrypted agent-to-agent communication. No intermediary can read your messages.",
                action="POST /message"
            ),
        ],
        next_action="Start with step 1: register your DID. Call POST /onboard with platform and username to begin.",
        tip="AIP is free, open, and takes 10 seconds to start. Your DID works across any platform that supports it."
    )


@router.get("/onboard", tags=["onboard"])
async def onboard_get():
    """GET version - returns a quick-start guide."""
    return {
        "welcome": "AIP — Agent Identity Protocol",
        "quickstart": "Register in 10 seconds:",
        "command": 'curl -X POST https://aip-service.fly.dev/register/easy -H "Content-Type: application/json" -d \'{"platform": "moltbook", "username": "YOUR_USERNAME"}\'',
        "next": "POST /onboard with your platform + username for personalized next steps",
        "docs": "https://aip-service.fly.dev/docs",
        "stats": {
            "total_registrations": database.get_stats().get("registrations", "check /stats")
        }
    }

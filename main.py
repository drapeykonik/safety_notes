import os
import random
from datetime import datetime

from cryptography.hazmat.primitives.ciphers import modes, algorithms, base
import binascii
from fastapi import Depends, FastAPI
from crypto.ecc import scalar_mult
from crypto.ecdh import make_keypair
from src.db import User, create_db_and_tables, get_async_session
from src.schemas import UserCreate, UserRead, UserUpdate, Note, Key
from src.service import NoteService, UserService
from src.settings import KEY_EXPIRATION_TIME
from src.users import auth_backend, current_active_user, fastapi_users

app = FastAPI()

app.include_router(
    fastapi_users.get_auth_router(auth_backend), prefix="/auth/jwt", tags=["auth"]
)
app.include_router(
    fastapi_users.get_register_router(UserRead, UserCreate),
    prefix="/auth",
    tags=["auth"],
)
app.include_router(
    fastapi_users.get_reset_password_router(),
    prefix="/auth",
    tags=["auth"],
)
app.include_router(
    fastapi_users.get_verify_router(UserRead),
    prefix="/auth",
    tags=["auth"],
)
app.include_router(
    fastapi_users.get_users_router(UserRead, UserUpdate),
    prefix="/users",
    tags=["users"],
)


@app.get("/")
async def authenticated_route(user: User = Depends(current_active_user)):
    return {"message": f"Hello {user.email}!"}


@app.get("/get_public_key")
async def exchange_public_keys(alice_public_key: Key, user: User = Depends(current_active_user),
                               session=Depends(get_async_session)):
    await UserService.save_public_key(session, user.id, alice_public_key)
    return {"public_key": os.getenv("public_key")}


@app.post("/create_note")
async def create_note(note: Note, user: User = Depends(current_active_user), session=Depends(get_async_session)):
    if (datetime.now() - user.pk_updated_at).seconds > KEY_EXPIRATION_TIME:
        return {"message": "handshake required"}
    note_name, note_message, note_iv = note.name, note.message, note.iv
    try:
        note.name, note.message = await NoteService.decrypt_note(user, note, note_iv)
        await NoteService.create_note(session, user.id, note, note_iv)
        note.name, note.message = note_name, note_message
    except BaseException as e:
        print(e)
        return {"message": "ECDH error"}
    return {"message": note, "iv": note_iv}


@app.get("/get_notes")
async def get_notes(user: User = Depends(current_active_user), session=Depends(get_async_session)):
    if (datetime.now() - user.pk_updated_at).seconds > KEY_EXPIRATION_TIME:
        return {"message": "handshake required"}
    iv = random.randbytes(16)
    notes = await NoteService.get_user_notes(session, user.id, iv)
    shared_secret = scalar_mult(int(os.getenv('private_key')), eval(user.public_key))
    password = shared_secret[0].to_bytes(128, 'big')
    cipher = base.Cipher(
        algorithms.IDEA(binascii.unhexlify(password)),
        modes.CFB(binascii.unhexlify(iv))
    )
    encryptor = cipher.encryptor()
    try:
        for note in notes:
            note.name = str(encryptor.update(binascii.unhexlify(note.name)) + encryptor.finalize())
            note.message = str(encryptor.update(binascii.unhexlify(note.message)) + encryptor.finalize())
    except BaseException:
        return {"message": "ECDH error"}
    return {"message": notes, "iv": iv}


@app.post("/edit_note")
async def edit_note(note: Note, user: User = Depends(current_active_user),
                    session=Depends(get_async_session)):
    if (datetime.now() - user.pk_updated_at).seconds > KEY_EXPIRATION_TIME:
        return {"message": "handshake required"}
    try:
        #iv = random.randbytes(16)
        note_name, note_message, note_iv = note.name, note.message, note.iv
        note.name, note.message = await NoteService.decrypt_note(user, note, note_iv)
        await NoteService.update_note(session, note.name, note.message, user.id, note_iv)
        note.name, note.message = note_name, note_message
    except BaseException:
        return {"message": "ECDH error"}
    return {"message": note, "iv": note_iv}


@app.delete("/delete_note")
async def delete_note(note: Note, user: User = Depends(current_active_user), session=Depends(get_async_session)):
    if (datetime.now() - user.pk_updated_at).seconds > KEY_EXPIRATION_TIME:
        return {"message": "handshake required"}
    try:
        iv = random.randbytes(16)
        note.name, note.message = await NoteService.decrypt_note(user, note, iv)
        deleted_note = await NoteService.delete_note(session, user.id, note)
    except BaseException:
        return {"message": "ECDH error"}
    return {"message": deleted_note, "iv": iv}


@app.on_event("startup")
async def on_startup():
    if 'private_key' not in os.environ:
        bob_private_key, bob_public_key = make_keypair()
        os.environ['private_key'] = str(bob_private_key)
        os.environ['public_key'] = str(bob_public_key)
        print('keys were created')

    await create_db_and_tables()

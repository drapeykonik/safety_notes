import os
from datetime import datetime
from uuid import UUID
from cryptography.hazmat.primitives.ciphers import modes, algorithms, base
import binascii
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from crypto.ecc import scalar_mult
from src import schemas, models


class UserService:
    @staticmethod
    async def save_public_key(session: AsyncSession, user_id: UUID, key: schemas.Key):
        user = await session.get(models.User, {'id': user_id})
        user.public_key = key.public_key
        user.pk_updated_at = datetime.now()
        await session.commit()
        await session.refresh(user)
        return user

class NoteService:
    @staticmethod
    async def decrypt_note(user, note, iv):
        shared_secret = scalar_mult(int(os.getenv('private_key')), eval(user.public_key))
        password = shared_secret[0].to_bytes(128, 'big')
        cipher = base.Cipher(
            algorithms.IDEA(binascii.unhexlify(password)),
            modes.CFB(binascii.unhexlify(iv))
        )
        decryptor = cipher.decryptor()
        name = decryptor.update(binascii.unhexlify(eval(note.name)))
        name += decryptor.finalize()
        message = decryptor.update(binascii.unhexlify(eval(note.message)))
        message += decryptor.finalize()
        return name, message

    @staticmethod
    async def create_note(session: AsyncSession, user_id: UUID, note: schemas.Note, iv):
        user = await session.get(models.User, {'id': user_id})
        db_password = int(os.getenv('private_key')).to_bytes(128, 'big')
        cipher = base.Cipher(
            algorithms.IDEA(binascii.unhexlify(db_password)),
            modes.CFB(binascii.unhexlify(iv))
        )
        encryptor = cipher.encryptor()
        note = models.Note(
            user_id=user.id,
            name=note.name,
            message=str(encryptor.update(binascii.unhexlify(note.message)) + encryptor.finalize())
        )
        decrypted_note = models.Note(
            user_id=user.id,
            name=note.name,
            message=note.message
        )
        session.add(note)
        await session.commit()
        await session.refresh(note)
        return decrypted_note

    @staticmethod
    async def get_user_notes(session: AsyncSession, user_id: UUID, iv):
        stmt = select(models.User).where(models.User.id == user_id).options(selectinload(models.User.notes))
        result = await session.execute(stmt)
        user = result.scalars().one()
        db_password = int(os.getenv('private_key')).to_bytes(128, 'big')
        cipher = base.Cipher(
            algorithms.IDEA(binascii.unhexlify(db_password)),
            modes.CFB(binascii.unhexlify(iv))
        )
        decryptor = cipher.decryptor()
        for note in user.notes:
            note.message = decryptor.update(eval(note.message)) + decryptor.finalize()
        return user.notes

    @staticmethod
    async def update_note(session: AsyncSession, note_name: str, note_message: str, user_id: UUID, iv):
        stmt = select(models.Note).where(models.Note.name == note_name)
        notes = await session.execute(stmt)
        note_from_db = notes.scalars().one()

        if note_from_db.user_id != user_id:
            return "This is not your note, you can't edit it"
        db_password = int(os.getenv('private_key')).to_bytes(128, 'big')
        cipher = base.Cipher(
            algorithms.IDEA(binascii.unhexlify(db_password)),
            modes.CFB(binascii.unhexlify(iv))
        )
        encryptor = cipher.decryptor()
        note_from_db.message = str(encryptor.update(note_message.encode()))

        await session.commit()
        await session.refresh(note_from_db)
        return models.Note(
            user_id=user_id,
            name=note_name,
            message=note_message
        )

    @staticmethod
    async def delete_note(session, user_id, note):
        stmt = select(models.Note).where(models.Note.name == note.name)
        notes = await session.execute(stmt)
        note_from_db = notes.scalars().one()
        if note_from_db.user_id != user_id:
            return "This is not your note, you can't delete it"
        await session.delete(note_from_db)
        await session.commit()

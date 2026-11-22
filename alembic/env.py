from logging.config import fileConfig

from alembic import context

from nexus_sec.database import Base
from nexus_sec.database import engine
from nexus_sec import models  # noqa: F401  (registers tables on Base.metadata)

if context.config.config_file_name is not None:
    fileConfig(context.config.config_file_name, disable_existing_loggers=False)

target_metadata = Base.metadata


def run_migrations_offline():
    context.configure(
        url=str(engine.url),
        target_metadata=target_metadata,
        literal_binds=True,
        render_as_batch=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online():
    with engine.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            # SQLite can't ALTER most things; batch mode rebuilds tables
            render_as_batch=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()

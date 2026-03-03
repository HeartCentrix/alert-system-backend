"""create user_locations and user_location_history tables

Revision ID: location_audience_v1
Revises: 
Create Date: 2026-03-04

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = 'location_audience_v1'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create enum types
    sa.Enum('MANUAL', 'GEOFENCE', name='userlocationassignmenttype').create(op.get_bind())
    sa.Enum('ACTIVE', 'INACTIVE', name='userlocationstatus').create(op.get_bind())
    
    # Create user_locations table
    op.create_table('user_locations',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('location_id', sa.Integer(), nullable=False),
        sa.Column('assignment_type', sa.Enum('MANUAL', 'GEOFENCE', name='userlocationassignmenttype'), nullable=False),
        sa.Column('status', sa.Enum('ACTIVE', 'INACTIVE', name='userlocationstatus'), nullable=False),
        sa.Column('detected_latitude', sa.Float(), nullable=True),
        sa.Column('detected_longitude', sa.Float(), nullable=True),
        sa.Column('distance_from_center_miles', sa.Float(), nullable=True),
        sa.Column('assigned_by_id', sa.Integer(), nullable=True),
        sa.Column('notes', sa.Text(), nullable=True),
        sa.Column('assigned_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['assigned_by_id'], ['users.id'], ),
        sa.ForeignKeyConstraint(['location_id'], ['locations.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create indexes for user_locations
    op.create_index(op.f('ix_user_locations_id'), 'user_locations', ['id'], unique=False)
    op.create_index(op.f('ix_user_locations_user_id'), 'user_locations', ['user_id'], unique=False)
    op.create_index(op.f('ix_user_locations_location_id'), 'user_locations', ['location_id'], unique=False)
    
    # Create user_location_history table
    op.create_table('user_location_history',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('location_id', sa.Integer(), nullable=False),
        sa.Column('user_location_id', sa.Integer(), nullable=True),
        sa.Column('action', sa.String(length=50), nullable=False),
        sa.Column('assignment_type', sa.Enum('MANUAL', 'GEOFENCE', name='userlocationassignmenttype'), nullable=True),
        sa.Column('previous_status', sa.Enum('ACTIVE', 'INACTIVE', name='userlocationstatus'), nullable=True),
        sa.Column('new_status', sa.Enum('ACTIVE', 'INACTIVE', name='userlocationstatus'), nullable=True),
        sa.Column('triggered_by_user_id', sa.Integer(), nullable=True),
        sa.Column('reason', sa.Text(), nullable=True),
        sa.Column('detected_latitude', sa.Float(), nullable=True),
        sa.Column('detected_longitude', sa.Float(), nullable=True),
        sa.Column('distance_from_center_miles', sa.Float(), nullable=True),
        sa.Column('ip_address', sa.String(length=45), nullable=True),
        sa.Column('user_agent', sa.String(length=500), nullable=True),
        sa.Column('extra_data', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['location_id'], ['locations.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['triggered_by_user_id'], ['users.id'], ),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['user_location_id'], ['user_locations.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create indexes for user_location_history
    op.create_index(op.f('ix_user_location_history_id'), 'user_location_history', ['id'], unique=False)
    op.create_index(op.f('ix_user_location_history_user_id'), 'user_location_history', ['user_id'], unique=False)
    op.create_index(op.f('ix_user_location_history_location_id'), 'user_location_history', ['location_id'], unique=False)
    op.create_index(op.f('ix_user_location_history_created_at'), 'user_location_history', ['created_at'], unique=False)
    
    # Add latitude/longitude to users table if not exists (for primary location tracking)
    # Note: This might already exist, so we use if_not_exists logic
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    columns = [col['name'] for col in inspector.get_columns('users')]
    
    if 'latitude' not in columns:
        op.add_column('users', sa.Column('latitude', sa.Float(), nullable=True))
    if 'longitude' not in columns:
        op.add_column('users', sa.Column('longitude', sa.Float(), nullable=True))


def downgrade() -> None:
    # Drop indexes
    op.drop_index(op.f('ix_user_location_history_created_at'), table_name='user_location_history')
    op.drop_index(op.f('ix_user_location_history_location_id'), table_name='user_location_history')
    op.drop_index(op.f('ix_user_location_history_user_id'), table_name='user_location_history')
    op.drop_index(op.f('ix_user_location_history_id'), table_name='user_location_history')
    
    op.drop_index(op.f('ix_user_locations_location_id'), table_name='user_locations')
    op.drop_index(op.f('ix_user_locations_user_id'), table_name='user_locations')
    op.drop_index(op.f('ix_user_locations_id'), table_name='user_locations')
    
    # Drop tables
    op.drop_table('user_location_history')
    op.drop_table('user_locations')
    
    # Drop enum types
    sa.Enum(name='userlocationassignmenttype').drop(op.get_bind())
    sa.Enum(name='userlocationstatus').drop(op.get_bind())
    
    # Remove latitude/longitude from users table
    op.drop_column('users', 'longitude')
    op.drop_column('users', 'latitude')

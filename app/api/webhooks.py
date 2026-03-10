@router.get("/incoming-messages", response_model=List[IncomingMessageResponse])
def get_incoming_messages(
    limit: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """View incoming messages (authenticated users only).

    Args:
        limit: Maximum number of results (1-500, default 50)

    Access Control:
        - Manager and Admin roles: Can see all incoming messages
        - Viewer role: Can only see their own incoming messages
    """
    # Query with user relationship to include user_name in response
    query = (
        db.query(IncomingMessage)
        .outerjoin(User, IncomingMessage.user_id == User.id)
    )

    # Viewer-role users can only see their own incoming messages
    if current_user.role == UserRole.VIEWER:
        query = query.filter(IncomingMessage.user_id == current_user.id)

    messages = (
        query
        .order_by(desc(IncomingMessage.received_at))
        .limit(limit)
        .all()
    )

    # Build response with user_name from related user
    result = []
    for msg in messages:
        result.append(
            {
                "id": msg.id,
                "from_number": msg.from_number,
                "body": msg.body,
                "channel": msg.channel,
                "user_id": msg.user_id,
                "user_email": msg.user.email if msg.user else msg.user_email,
                "user_name": msg.user.full_name if msg.user else None,
                "notification_id": msg.notification_id,
                "is_processed": msg.is_processed,
                "received_at": msg.received_at,
            }
        )

    return result
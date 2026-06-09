from celery import shared_task


@shared_task
def render_campaign(
    campaign_id: str,
) -> None:
    campaign_slots.acquire()
    try:
        result = campaign_renderer.render(
            campaign_id
        )
        campaign_repository.save(
            campaign_id,
            result,
        )
    finally:
        campaign_slots.release()

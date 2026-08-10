import os
import re
import frontmatter
from pathlib import Path
from sqlalchemy.orm import Session
from app.database import SessionLocal, engine
from app.models import Base, Article, Tag, User

# Ensure tables exist
Base.metadata.create_all(bind=engine)

def convert_obsidian_wikilinks(text: str) -> str:
    """ Converts [[Wiki Link|Display Text]] or [[Wiki Link]] into [Display Text](/kb/slug) """
    def replace_link(match):
        target = match.group(1).strip()
        display = match.group(2).strip() if match.group(2) else target
        slug = re.sub(r'[^a-z0-9]+', '-', target.lower()).strip('-')
        return f"[{display}](/kb/{slug})"

    return re.sub(r'\[\[([^\|\]]+)(?:\|([^\]]+))?\]\]', replace_link, text)

def get_or_create_tag(db: Session, tag_name: str) -> Tag:
    clean_name = re.sub(r'[^a-zA-Z0-9_-]', '', tag_name.lower().strip())
    tag = db.query(Tag).filter(Tag.name == clean_name).first()
    if not tag:
        tag = Tag(name=clean_name)
        db.add(tag)
        db.commit()
        db.refresh(tag)
    return tag

def import_vault(vault_path: str):
    db: Session = SessionLocal()
    
    # Get or create system admin author
    author = db.query(User).filter(User.username == "admin").first()
    if not author:
        author = User(username="admin", email="admin@askpc.cc")
        db.add(author)
        db.commit()

    imported_count = 0
    vault = Path(vault_path)

    for md_file in vault.rglob("*.md"):
        post = frontmatter.load(md_file)
        
        raw_title = post.get("title", md_file.stem)
        slug = re.sub(r'[^a-z0-9]+', '-', raw_title.lower()).strip('-')
        
        # Convert Obsidian Wikilinks
        cleaned_content = convert_obsidian_wikilinks(post.content)

        # Check existing article
        article = db.query(Article).filter(Article.slug == slug).first()
        if not article:
            article = Article(
                title=raw_title,
                slug=slug,
                category=post.get("category", "General"),
                difficulty=post.get("difficulty", "Beginner"),
                content_markdown=cleaned_content,
                author_id=author.id
            )
            db.add(article)
            db.commit()

        # Handle Tags
        raw_tags = post.get("tags", [])
        if isinstance(raw_tags, str):
            raw_tags = [t.strip() for t in raw_tags.split(",")]

        article.tags = []
        for tag_str in raw_tags:
            tag_obj = get_or_create_tag(db, tag_str)
            article.tags.append(tag_obj)

        db.commit()
        imported_count += 1
        print(f"✅ Imported KB Article: {raw_title} (slug: {slug})")

    db.close()
    print(f"\n🚀 Successfully imported {imported_count} notes from Obsidian Vault!")

if __name__ == "__main__":
    import sys
    path = sys.argv[1] if len(sys.argv) > 1 else "./obsidian_vault"
    if os.path.exists(path):
        import_vault(path)
    else:
        print(f"Directory '{path}' not found. Create folder '{path}' and put .md files inside.")
